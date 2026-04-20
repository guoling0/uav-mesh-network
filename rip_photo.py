#!/usr/bin/env python3
# rip_node.py
# Usage: sudo python3 rip_node.py <NODE_NAME> [RSSI_THRESHOLD]

import base64, os, sys, time, threading, json, cmd, select, tty, termios, uuid
from scapy.all import *

# ── Config ────────────────────────────────────────────────────────────────────
IFACE        = "wlan1"
BSSID        = "aa:bb:cc:dd:ee:ff"
BCAST_MAC    = "ff:ff:ff:ff:ff:ff"
OUI          = b'\x11\x22\x33'
CAT_VENDOR   = 0x7f
INF          = 16
RIP_INTERVAL = 0.02
TIMEOUT      = 5

RTX_INTERVAL = 0.001
RTX_MAX      = 2000

MY_NODE        = ""
RSSI_THRESHOLD = None

route_lock    = threading.Lock()
routing_table = {}

event_lock = threading.Lock()
event_log  = []
MAX_EVENTS = 20

PHOTO_PREFIX      = "__PHOTO__"
PHOTO_CHUNK_SIZE  = 512
PHOTO_ACK_TIMEOUT = 30.0
PHOTO_TX_DELAY    = 0.02
PHOTO_SAVE_DIR    = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "received_photos")
photo_rx_lock = threading.Lock()
photo_rx      = {}

# ── RX Dedup Table ────────────────────────────────────────────────────────────
# Tracks data packets we have already processed (as the final destination).
# Key   : msg_id of the original DATA packet
# Value : { "ack_msg": str (the ack text we replied with),
#            "ts"     : float (time we first processed it) }
# Entries are purged after DEDUP_TTL seconds.
DEDUP_TTL  = 30.0
dedup_lock = threading.Lock()
rx_seen    = {}

def dedup_check(msg_id):
    """Return stored ack_msg if already processed, else None."""
    with dedup_lock:
        entry = rx_seen.get(msg_id)
        if entry:
            return entry["ack_msg"]
    return None

def dedup_record(msg_id, ack_msg):
    """Record that we have processed msg_id and replied with ack_msg."""
    with dedup_lock:
        rx_seen[msg_id] = {"ack_msg": ack_msg, "ts": time.time()}

def dedup_expire():
    """Background thread: purge old dedup entries."""
    while True:
        time.sleep(10.0)
        cutoff = time.time() - DEDUP_TTL
        with dedup_lock:
            for mid in [m for m, e in rx_seen.items() if e["ts"] < cutoff]:
                del rx_seen[mid]

# ── TX Queue ──────────────────────────────────────────────────────────────────
# Only DATA packets (ack_flag='0') are enqueued for reliable delivery.
# ACK packets are sent directly (fire-and-forget); reliability is achieved
# because the sender keeps retransmitting the DATA until it gets an ACK.
#
# Entry fields:
#   msg_id    : str    unique ID for this data message
#   src       : str
#   dst       : str
#   msg       : str    payload text
#   ttl       : int
#   attempts  : int    number of actual transmissions so far
#   last_sent : float  timestamp of last actual transmission
#   acked     : bool   True once the peer's ACK arrived
#   waiting   : bool   True while parked waiting for a route
txq_lock = threading.Lock()
tx_queue = {}

def push_event(msg):
    with event_lock:
        event_log.append(msg)
        if len(event_log) > MAX_EVENTS:
            event_log.pop(0)

TAG_RIP  = b'R'
TAG_DATA = b'D'

live_route_active = threading.Event()

def make_photo_message(kind, **fields):
    payload = {"type": kind, **fields}
    return PHOTO_PREFIX + json.dumps(payload, separators=(",", ":"))

def parse_photo_message(msg):
    if not msg.startswith(PHOTO_PREFIX):
        return None
    try:
        packet = json.loads(msg[len(PHOTO_PREFIX):])
    except Exception:
        return None
    if not isinstance(packet, dict):
        return None
    return packet

def safe_photo_name(name):
    safe = os.path.basename(name)
    return safe or "photo.bin"

def next_photo_path(filename):
    os.makedirs(PHOTO_SAVE_DIR, exist_ok=True)
    safe = safe_photo_name(filename)
    root, ext = os.path.splitext(safe)
    path = os.path.join(PHOTO_SAVE_DIR, safe)
    suffix = 1
    while os.path.exists(path):
        path = os.path.join(PHOTO_SAVE_DIR, f"{root}_{suffix}{ext}")
        suffix += 1
    return path

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_rssi(pkt):
    try:
        if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], 'dBm_AntSignal'):
            return pkt[RadioTap].dBm_AntSignal
    except Exception:
        pass
    return None

def rssi_ok(rssi):
    if RSSI_THRESHOLD is None:
        return True
    if rssi is None:
        return True
    return rssi >= RSSI_THRESHOLD

def send_frame(payload: bytes):
    dot11 = Dot11(type=0, subtype=13,
                  addr1=BCAST_MAC, addr2=RandMAC(), addr3=BSSID)
    raw = bytes([CAT_VENDOR]) + OUI + payload
    sendp(RadioTap() / dot11 / Raw(load=raw), iface=IFACE, verbose=0)

def log(msg, console=False):
    push_event(msg)
    if console and not live_route_active.is_set():
        print(f"\r{msg}\n(rip) ", end="", flush=True)

# ── Routing ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def update_route(dest, metric, next_hop):
    if dest == MY_NODE:
        return False
    with route_lock:
        old = routing_table.get(dest)
        if metric >= INF:
            if old and old["metric"] < INF:
                routing_table[dest] = {"metric": INF, "next_hop": next_hop,
                                       "updated": time.time()}
                return True
            return False
        if old is None:
            routing_table[dest] = {"metric": metric, "next_hop": next_hop,
                                   "updated": time.time()}
            return True
        if next_hop == old["next_hop"]:
            old["updated"] = time.time()
            if metric != old["metric"]:
                old["metric"] = metric
                return True
            return False
        if metric < old["metric"]:
            routing_table[dest] = {"metric": metric, "next_hop": next_hop,
                                   "updated": time.time()}
            return True
    return False

def lookup_next_hop(dst):
    with route_lock:
        entry = routing_table.get(dst)
    if entry is None or entry["metric"] >= INF:
        return None
    return entry["next_hop"]

def send_rip_update():
    with route_lock:
        snap = dict(routing_table)
    snap[MY_NODE] = {"metric": 0, "next_hop": MY_NODE}
    payload = TAG_RIP + MY_NODE.encode() + b'|' + json.dumps(
        {d: v["metric"] for d, v in snap.items()}
    ).encode()
    send_frame(payload)

def rip_sender():
    while True:
        send_rip_update()
        time.sleep(RIP_INTERVAL)

def expire_routes():
    while True:
        time.sleep(RIP_INTERVAL)
        now = time.time()
        with route_lock:
            for dest in list(routing_table):
                if now - routing_table[dest]["updated"] > TIMEOUT:
                    log(f"[EXPIRE] Route to {dest} expired")
                    del routing_table[dest]

# ── Frame Builder ─────────────────────────────────────────────────────────────
# Wire format:
#   TAG_DATA + src|dst|next_hop|ttl|ack_flag|msg_id|msg
#
# ack_flag='0'  -> DATA packet  (reliable, queued)
# ack_flag='1'  -> ACK  packet  (fire-and-forget, never queued)

def build_and_send(src, dst, next_hop, ttl, ack_flag, msg_id, msg):
    payload = (TAG_DATA +
               f"{src}|{dst}|{next_hop}|{ttl}|{ack_flag}|{msg_id}|{msg}".encode())
    send_frame(payload)

# ── ACK: fire-and-forget (no queue) ──────────────────────────────────────────
def send_ack_direct(dst, msg_id, ack_msg):
    """
    Send a single ACK frame directly without queuing.
    Called both on first receipt and on every duplicate receipt of the same
    DATA msg_id.  Because the DATA sender retransmits until it gets this ACK,
    we do not need to guarantee ACK delivery ourselves -- we just keep
    re-sending the ACK every time the duplicate DATA arrives.
    """
    nh = lookup_next_hop(dst)
    if nh is None:
        log(f"[WARN] Cannot send ACK to {dst}: no route", console=True)
        return
    log(f"[ACK-TX] {MY_NODE} -> {dst} via {nh} (msg_id={msg_id}) : \"{ack_msg}\"",
        console=True)
    build_and_send(MY_NODE, dst, nh, 15, '1', msg_id, ack_msg)

# ── TX Queue Operations (DATA only) ──────────────────────────────────────────
def txq_enqueue(src, dst, msg, ttl=15):
    """
    Create a reliable DATA entry in the TX queue and attempt first send.
    Returns msg_id.
    """
    msg_id = uuid.uuid4().hex[:8]
    entry = {
        "msg_id"   : msg_id,
        "src"      : src,
        "dst"      : dst,
        "msg"      : msg,
        "ttl"      : ttl,
        "attempts" : 0,
        "last_sent": 0.0,
        "acked"    : False,
        "waiting"  : False,
    }
    with txq_lock:
        tx_queue[msg_id] = entry
    _txq_do_send(entry)
    return msg_id

def _txq_do_send(entry):
    """
    Re-lookup route every time (never cache next_hop).

    Outcomes:
      Route found   -> transmit, attempts += 1, last_sent = now
      Route missing -> set waiting=True, do NOT touch attempts/last_sent
      Already acked -> skip
    """
    if entry["acked"]:
        return

    dst = entry["dst"]
    nh  = lookup_next_hop(dst)

    if nh is None:
        if not entry["waiting"]:
            entry["waiting"] = True
            log(f"[TXQ-WAIT] msg_id={entry['msg_id']} dst={dst} "
                f"no route, parked until route becomes available")
        return

    if entry["waiting"]:
        entry["waiting"] = False
        log(f"[TXQ-RESUME] msg_id={entry['msg_id']} dst={dst} "
            f"route via {nh} found, resuming")

    with txq_lock:
        entry["attempts"] += 1
        entry["last_sent"] = time.time()

    log(f"[TX] {entry['src']} -> {dst} via {nh} "
        f"(msg_id={entry['msg_id']} attempt={entry['attempts']}/{RTX_MAX}) "
        f": \"{entry['msg']}\"")
    build_and_send(entry["src"], dst, nh,
                   entry["ttl"], '0',
                   entry["msg_id"], entry["msg"])

def txq_ack(msg_id):
    """
    Mark a DATA entry as acknowledged.
    Called when an ACK frame carrying this msg_id arrives at the originator.
    """
    with txq_lock:
        entry = tx_queue.get(msg_id)
        if entry and not entry["acked"]:
            entry["acked"] = True
            log(f"[TXQ-DONE] msg_id={msg_id} dst={entry['dst']} "
                f"confirmed after {entry['attempts']} attempt(s)",
                console=True)

def txq_show():
    lines = []
    with txq_lock:
        if not tx_queue:
            lines.append("  (tx queue empty)")
            return lines
        lines.append(f"  {'msg_id':<10} {'src':<5} {'dst':<5} "
                     f"{'att':<5} {'state':<10} msg")
        lines.append("  " + "-" * 60)
        for e in tx_queue.values():
            if e["acked"]:
                state = "ACKED"
            elif e["waiting"]:
                state = "WAITING"
            else:
                state = f"att={e['attempts']}/{RTX_MAX}"
            lines.append(f"  {e['msg_id']:<10} {e['src']:<5} {e['dst']:<5} "
                         f"{e['attempts']:<5} {state:<10} \"{e['msg'][:24]}\"")
    return lines

def txq_cancel(msg_id):
    with txq_lock:
        if msg_id in tx_queue:
            del tx_queue[msg_id]
            log(f"[TXQ-CANCEL] msg_id={msg_id} cancelled by user", console=True)
        else:
            log(f"[TXQ-CANCEL] msg_id={msg_id} not found in queue", console=True)

def wait_for_tx_ack(msg_id, timeout=PHOTO_ACK_TIMEOUT):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with txq_lock:
            entry = tx_queue.get(msg_id)
            if entry is None:
                return False
            if entry["acked"]:
                return True
        time.sleep(0.05)
    return False

def send_reliable_and_wait(dst, msg, ttl=15, timeout=PHOTO_ACK_TIMEOUT):
    msg_id = txq_enqueue(MY_NODE, dst, msg, ttl=ttl)
    return wait_for_tx_ack(msg_id, timeout), msg_id

def handle_photo_meta(src, packet):
    transfer_id = str(packet.get("id", "")).strip()
    if not transfer_id:
        log(f"[PHOTO-RX] Invalid photo meta from {src}", console=True)
        return "PHOTO-ERR"

    try:
        total_chunks = int(packet.get("total", 0))
        file_size = int(packet.get("size", 0))
    except Exception:
        log(f"[PHOTO-RX] Invalid photo meta fields from {src}", console=True)
        return "PHOTO-ERR"

    if total_chunks <= 0 or file_size < 0:
        log(f"[PHOTO-RX] Invalid photo meta values from {src}", console=True)
        return "PHOTO-ERR"

    filename = safe_photo_name(str(packet.get("name", f"{transfer_id}.bin")))
    created = False
    with photo_rx_lock:
        if transfer_id not in photo_rx:
            photo_rx[transfer_id] = {
                "src": src,
                "name": filename,
                "size": file_size,
                "total": total_chunks,
                "chunks": {},
                "started": time.time(),
            }
            created = True

    if created:
        log(f"[PHOTO-RX] Prepare {filename} from {src} "
            f"({file_size} bytes, {total_chunks} chunks)", console=True)
    return f"PHOTO-META:{transfer_id}"

def handle_photo_chunk(src, packet):
    transfer_id = str(packet.get("id", "")).strip()
    if not transfer_id:
        log(f"[PHOTO-RX] Invalid photo chunk from {src}", console=True)
        return "PHOTO-ERR"

    try:
        index = int(packet.get("index", -1))
        chunk = base64.b64decode(packet.get("data", "").encode())
    except Exception:
        log(f"[PHOTO-RX] Invalid photo chunk payload from {src}", console=True)
        return "PHOTO-ERR"

    progress_msg = None
    complete_entry = None
    with photo_rx_lock:
        entry = photo_rx.get(transfer_id)
        if entry is None:
            log(f"[PHOTO-RX] Missing meta for transfer {transfer_id} from {src}",
                console=True)
            return "PHOTO-NOMETA"

        if index < 0 or index >= entry["total"]:
            log(f"[PHOTO-RX] Invalid chunk index {index} for {transfer_id}",
                console=True)
            return "PHOTO-ERR"

        if index not in entry["chunks"]:
            entry["chunks"][index] = chunk

        received = len(entry["chunks"])
        total = entry["total"]
        if received == 1 or received == total or received % 10 == 0:
            progress_msg = (f"[PHOTO-RX] {entry['name']} from {src}: "
                            f"{received}/{total} chunks")

        if received == total and all(i in entry["chunks"] for i in range(total)):
            file_bytes = b"".join(entry["chunks"][i] for i in range(total))
            complete_entry = {
                "name": entry["name"],
                "size": entry["size"],
                "data": file_bytes,
            }
            del photo_rx[transfer_id]

    if progress_msg:
        log(progress_msg, console=True)

    if complete_entry is not None:
        out_path = next_photo_path(complete_entry["name"])
        try:
            with open(out_path, "wb") as fh:
                fh.write(complete_entry["data"])
        except OSError as exc:
            log(f"[PHOTO-RX] Save failed for {complete_entry['name']}: {exc}",
                console=True)
            return "PHOTO-SAVEERR"

        actual_size = len(complete_entry["data"])
        expect_size = complete_entry["size"]
        if actual_size != expect_size:
            log(f"[PHOTO-RX] Saved {complete_entry['name']} -> {out_path} "
                f"({actual_size} bytes, expected {expect_size})", console=True)
        else:
            log(f"[PHOTO-RX] Saved {complete_entry['name']} -> {out_path} "
                f"({actual_size} bytes)", console=True)

    return f"PHOTO-CHUNK:{index}"

def handle_incoming_message(src, msg, msg_id, rssi_str):
    packet = parse_photo_message(msg)
    if packet is None:
        ack_msg = f"[ACK] {msg}"
        log(f"[RX] {src} -> {MY_NODE} : \"{msg}\" "
            f"({rssi_str}) msg_id={msg_id}", console=True)
        return ack_msg

    pkt_type = packet.get("type")
    if pkt_type == "meta":
        return handle_photo_meta(src, packet)
    if pkt_type == "chunk":
        return handle_photo_chunk(src, packet)

    log(f"[PHOTO-RX] Unknown packet type from {src}: {pkt_type}", console=True)
    return "PHOTO-ERR"

def _send_photo_worker(dst, photo_path):
    photo_path = os.path.abspath(os.path.expanduser(photo_path))
    if not os.path.isfile(photo_path):
        log(f"[PHOTO-TX] File not found: {photo_path}", console=True)
        return

    try:
        with open(photo_path, "rb") as fh:
            file_bytes = fh.read()
    except OSError as exc:
        log(f"[PHOTO-TX] Cannot read {photo_path}: {exc}", console=True)
        return

    transfer_id = uuid.uuid4().hex[:8]
    filename = os.path.basename(photo_path)
    total_chunks = max(1, (len(file_bytes) + PHOTO_CHUNK_SIZE - 1) //
                       PHOTO_CHUNK_SIZE)

    log(f"[PHOTO-TX] Sending {filename} -> {dst} "
        f"({len(file_bytes)} bytes, {total_chunks} chunks)", console=True)

    meta_msg = make_photo_message("meta",
                                  id=transfer_id,
                                  name=filename,
                                  size=len(file_bytes),
                                  total=total_chunks)
    ok, _ = send_reliable_and_wait(dst, meta_msg)
    if not ok:
        log(f"[PHOTO-TX] Meta failed for {filename} -> {dst}", console=True)
        return

    for index in range(total_chunks):
        start = index * PHOTO_CHUNK_SIZE
        chunk = file_bytes[start:start + PHOTO_CHUNK_SIZE]
        chunk_msg = make_photo_message("chunk",
                                       id=transfer_id,
                                       index=index,
                                       data=base64.b64encode(chunk).decode())
        ok, _ = send_reliable_and_wait(dst, chunk_msg)
        if not ok:
            log(f"[PHOTO-TX] Chunk {index + 1}/{total_chunks} failed "
                f"for {filename}", console=True)
            return
        if index == 0 or index + 1 == total_chunks or (index + 1) % 10 == 0:
            log(f"[PHOTO-TX] {filename} -> {dst}: "
                f"{index + 1}/{total_chunks} chunks ACKed", console=True)
        time.sleep(PHOTO_TX_DELAY)

    log(f"[PHOTO-TX] Completed {filename} -> {dst}", console=True)

def send_photo(dst, photo_path):
    if dst == MY_NODE:
        log(f"[ERR] Cannot send photo to self", console=True)
        return
    threading.Thread(target=_send_photo_worker,
                     args=(dst, photo_path),
                     daemon=True).start()

def txq_worker():
    """
    Background retransmit loop. Runs every second.

    Per-entry logic:
      acked=True  and age > 10s  -> purge
      waiting=True               -> re-check route, send if available
      waiting=False:
        now - last_sent < RTX_INTERVAL -> skip
        attempts >= RTX_MAX            -> [TXQ-FAIL] purge
        else                           -> [TXQ-RTX] retransmit
    """
    while True:
        time.sleep(0.1)
        now = time.time()

        with txq_lock:
            all_entries = list(tx_queue.values())

        for entry in all_entries:
            mid = entry["msg_id"]

            if entry["acked"]:
                if now - entry["last_sent"] > 10.0:
                    with txq_lock:
                        tx_queue.pop(mid, None)
                continue

            if entry["waiting"]:
                _txq_do_send(entry)
                continue

            if now - entry["last_sent"] < RTX_INTERVAL:
                continue

            if entry["attempts"] >= RTX_MAX:
                log(f"[TXQ-FAIL] msg_id={mid} dst={entry['dst']} "
                    f"gave up after {RTX_MAX} attempt(s)")
                with txq_lock:
                    tx_queue.pop(mid, None)
                continue

            log(f"[TXQ-RTX] msg_id={mid} dst={entry['dst']} "
                f"scheduling retransmit #{entry['attempts'] + 1}/{RTX_MAX}")
            _txq_do_send(entry)

# ── RX Handler ────────────────────────────────────────────────────────────────
def rx_handler(pkt):
    if not (pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 13):
        return
    if not (pkt.addr3 and pkt.addr3.lower() == BSSID.lower()):
        return

    raw = bytes(pkt[Dot11].payload)
    if len(raw) < 5 or raw[0] != CAT_VENDOR or raw[1:4] != OUI:
        return

    body = raw[4:]
    tag  = body[:1]
    data = body[1:]

    rssi     = get_rssi(pkt)
    rssi_str = f"{rssi}dBm" if rssi is not None else "N/A"

    # ── RIP Update ────────────────────────────────────────────────────────────
    if tag == TAG_RIP:
        parts = data.split(b'|', 1)
        if len(parts) != 2:
            return
        sender = parts[0].decode(errors='ignore')
        if sender == MY_NODE:
            return
        with route_lock:
            old_sender = routing_table.get(sender)
            was_direct = (
                old_sender is not None and
                old_sender["next_hop"] == sender and
                old_sender["metric"] < INF
            )
        if not rssi_ok(rssi):
            log(f"[RSSI-DROP] RIP from {sender} ignored "
                f"({rssi_str} < {RSSI_THRESHOLD}dBm threshold)")
            return
        try:
            adv = json.loads(parts[1].decode())
        except Exception:
            return
        direct_changed = update_route(sender, 1, sender)
        for dest, metric in adv.items():
            if dest == MY_NODE:
                continue
            update_route(dest, min(metric + 1, INF), sender)
        if direct_changed and not was_direct:
            log(f"[NEIGHBOR] {sender} ({rssi_str}) discovered", console=True)

    # ── Data Frame ────────────────────────────────────────────────────────────
    elif tag == TAG_DATA:
        try:
            fields = data.decode(errors='ignore').split('|', 6)
            src, dst, nxt, ttl_s, ack_flag, msg_id, msg = fields
            ttl = int(ttl_s)
        except Exception:
            return

        # Step 1: next_hop check — not me, ignore
        if nxt != MY_NODE:
            return

        # Step 2: dst check
        if dst == MY_NODE:
            if ack_flag == '1':
                # ── Incoming ACK: confirm the original DATA in our tx queue ──
                # msg_id here is the original DATA msg_id the sender echoes back
                log(f"[ACK] {src} -> {MY_NODE} : \"{msg}\" "
                    f"({rssi_str}) msg_id={msg_id}",
                    console=True)
                txq_ack(msg_id)

            else:
                # ── Incoming DATA ─────────────────────────────────────────────
                prev_ack = dedup_check(msg_id)
                if prev_ack is not None:
                    # Duplicate: we already processed this msg_id.
                    # Just re-send the same ACK (fire-and-forget).
                    # This naturally handles the case where our ACK was lost
                    # and the sender retransmitted the DATA.
                    log(f"[RX-DUP] {src} -> {MY_NODE} : duplicate msg_id={msg_id}, "
                        f"re-sending ACK",
                        console=True)
                    send_ack_direct(src, msg_id, prev_ack)
                else:
                    # First time seeing this msg_id: process and record
                    ack_msg = handle_incoming_message(src, msg, msg_id, rssi_str)
                    dedup_record(msg_id, ack_msg)
                    send_ack_direct(src, msg_id, ack_msg)

        else:
            # Step 3: not my destination, re-lookup and forward
            if ttl <= 0:
                log(f"[DROP] TTL=0 : {src} -> {dst}, dropped at {MY_NODE}")
                return
            nh = lookup_next_hop(dst)
            if nh is None:
                log(f"[DROP] No route to {dst} : {src} -> {dst}, "
                    f"dropped at {MY_NODE}")
                return
            kind = "ACK-FWD" if ack_flag == '1' else "FWD"
            log(f"[{kind}] {src} -> {dst} via {nh} (TTL:{ttl-1}) "
                f"at {MY_NODE} ({rssi_str}) msg_id={msg_id}",
                console=True)
            build_and_send(src, dst, nh, ttl - 1, ack_flag, msg_id, msg)

# ── Send Message (CLI entry point) ────────────────────────────────────────────
def send_message(dst, msg):
    if dst == MY_NODE:
        log(f"[ERR] Cannot send to self", console=True)
        return
    txq_enqueue(MY_NODE, dst, msg, ttl=15)

# ── Threshold control ─────────────────────────────────────────────────────────
def set_threshold(val):
    global RSSI_THRESHOLD
    RSSI_THRESHOLD = val
    thr = f"{val}dBm" if val is not None else "off"
    log(f"[CFG] RSSI threshold set to {thr}", console=True)

# ── Live Route Display ────────────────────────────────────────────────────────
CLEAR  = "\033[2J\033[H"
BOLD   = "\033[1m"
RESET  = "\033[0m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
RED    = "\033[31m"

def metric_color(m):
    if m == 0:   return GREEN
    if m <= 2:   return CYAN
    if m < INF:  return YELLOW
    return RED

def render_route_table():
    thr_str = f"{RSSI_THRESHOLD}dBm" if RSSI_THRESHOLD is not None else "off"
    lines = []
    lines.append(f"{BOLD}{'='*60}{RESET}")
    lines.append(f"{BOLD}  RIP Live Route Table   Node:{MY_NODE}   "
                 f"{time.strftime('%H:%M:%S')}   Threshold:{thr_str}{RESET}")
    lines.append(f"{BOLD}{'='*60}{RESET}")
    lines.append(f"{BOLD}{'Dest':<10} {'Metric':<8} {'NextHop':<14} {'Age(s)'}{RESET}")
    lines.append("-" * 60)
    with route_lock:
        snap = dict(routing_table)
    now = time.time()
    lines.append(f"{GREEN}{'*'+MY_NODE:<10} {'0':<8} {'local':<14} -{RESET}")
    if not snap:
        lines.append("  (no neighbours yet)")
    for dest, v in sorted(snap.items()):
        age = int(now - v["updated"])
        m   = v["metric"]
        ms  = str(m) if m < INF else "INF"
        col = metric_color(m)
        lines.append(f"{col}{dest:<10} {ms:<8} {v['next_hop']:<14} {age}{RESET}")
    lines.append(f"  {YELLOW}Press [q] to exit live view{RESET}")
    return "\n".join(lines)

def live_route_view():
    live_route_active.set()
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while True:
            sys.stdout.write(CLEAR + render_route_table())
            sys.stdout.flush()
            rlist, _, _ = select.select([sys.stdin], [], [], 1.0)
            if rlist:
                ch = sys.stdin.read(1)
                if ch.lower() == 'q':
                    break
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        live_route_active.clear()
        sys.stdout.write(CLEAR)
        sys.stdout.flush()

# ── CLI ───────────────────────────────────────────────────────────────────────
class RipCLI(cmd.Cmd):
    prompt = "(rip) "
    intro  = "RIP node ready. Type 'help' for commands."

    def do_route(self, _):
        """Enter live route table view (press q to exit)."""
        live_route_view()
        print("(rip) ", end="", flush=True)

    def do_send(self, line):
        """Send a message: send <NODE> <message>"""
        parts = line.split(' ', 1)
        if len(parts) < 2:
            print("Usage: send <NODE> <message>")
            return
        send_message(parts[0].strip(), parts[1].strip())

    def do_sendphoto(self, line):
        """Send a photo file: sendphoto <NODE> <image_path>"""
        parts = line.split(' ', 1)
        if len(parts) < 2:
            print("Usage: sendphoto <NODE> <image_path>")
            return
        photo_path = parts[1].strip().strip('"')
        send_photo(parts[0].strip(), photo_path)

    def do_queue(self, line):
        """Manage TX queue.
        queue show            -> list all entries with state
        queue cancel <msg_id> -> cancel and remove a pending entry
        """
        parts = line.strip().split()
        if not parts or parts[0] == 'show':
            for l in txq_show():
                print(l)
        elif parts[0] == 'cancel' and len(parts) == 2:
            txq_cancel(parts[1])
        else:
            print("Usage: queue show | queue cancel <msg_id>")

    def do_threshold(self, line):
        """Set or clear RSSI threshold.
        threshold -60   -> ignore RIP packets weaker than -60dBm
        threshold off   -> disable filter
        threshold       -> show current value
        """
        line = line.strip()
        if not line:
            thr = f"{RSSI_THRESHOLD}dBm" if RSSI_THRESHOLD is not None else "off"
            print(f"Current RSSI threshold: {thr}")
            return
        if line.lower() == 'off':
            set_threshold(None)
            return
        try:
            val = int(line)
            if val > 0:
                val = -val
            set_threshold(val)
        except ValueError:
            print("Usage: threshold <negative_int | off>  e.g. threshold -60")

    def do_quit(self, _):
        """Quit the program."""
        print("Bye.")
        sys.exit(0)

    def do_EOF(self, _):
        return self.do_quit(_)

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 rip_node.py <NODE_NAME> [RSSI_THRESHOLD]")
        print("  e.g. sudo python3 rip_node.py A -60")
        sys.exit(1)

    MY_NODE = sys.argv[1]

    if len(sys.argv) >= 3:
        try:
            val = int(sys.argv[2])
            if val > 0:
                val = -val
            RSSI_THRESHOLD = val
        except ValueError:
            print(f"Invalid RSSI threshold: {sys.argv[2]}")
            sys.exit(1)

    thr_str = f"{RSSI_THRESHOLD}dBm" if RSSI_THRESHOLD is not None else "off"
    print(f"[*] Node:{MY_NODE}  Iface:{IFACE}  Threshold:{thr_str}  "
          f"RTX_INTERVAL:{RTX_INTERVAL}s  RTX_MAX:{RTX_MAX}")

    threading.Thread(target=lambda: sniff(iface=IFACE, prn=rx_handler, store=0),
                     daemon=True).start()
    threading.Thread(target=rip_sender,    daemon=True).start()
    threading.Thread(target=expire_routes, daemon=True).start()
    threading.Thread(target=txq_worker,    daemon=True).start()
    threading.Thread(target=dedup_expire,  daemon=True).start()

    RipCLI().cmdloop()
