"""
RIP-2 Protocol Implementation
Based on RFC 2453
"""

import struct
import time
import threading
import random
from collections import defaultdict

# RIP Constants
RIP_VERSION = 2
INFINITY = 16
DEFAULT_METRIC = 1

# Command types
REQUEST = 1
RESPONSE = 2

# Timers (in seconds)
UPDATE_INTERVAL = 30
TIMEOUT = 180
GARBAGE_COLLECTION = 120

# Address Family
AF_INET = 2

class RIPEntry:
    """Represents a single RIP routing table entry"""
    def __init__(self, destination, subnet_mask, next_hop, metric, route_tag=0):
        self.destination = destination
        self.subnet_mask = subnet_mask
        self.next_hop = next_hop
        self.metric = min(metric, INFINITY)
        self.route_tag = route_tag
        self.timeout = time.time()
        self.garbage_timer = None
        self.changed = False
    
    def to_bytes(self):
        """Convert entry to RIP-2 wire format (20 bytes)"""
        parts = self.destination.split('.')
        dest_bytes = bytes([int(p) for p in parts])
        
        mask_parts = self.subnet_mask.split('.')
        mask_bytes = bytes([int(p) for p in mask_parts])
        
        hop_parts = self.next_hop.split('.')
        hop_bytes = bytes([int(p) for p in hop_parts])
        
        return struct.pack(
            '!HH4s4s4sI',
            AF_INET,           # Address Family Identifier
            self.route_tag,    # Route Tag
            dest_bytes,        # IP Address
            mask_bytes,        # Subnet Mask
            hop_bytes,         # Next Hop
            self.metric        # Metric
        )
    
    @staticmethod
    def from_bytes(data):
        """Parse RIP-2 entry from bytes"""
        if len(data) < 20:
            return None
        
        afi, tag, dest, mask, hop, metric = struct.unpack('!HH4s4s4sI', data[:20])
        
        if afi != AF_INET:
            return None
        
        destination = '.'.join(str(b) for b in dest)
        subnet_mask = '.'.join(str(b) for b in mask)
        next_hop = '.'.join(str(b) for b in hop)
        
        return RIPEntry(destination, subnet_mask, next_hop, metric, tag)


class RIPMessage:
    """RIP message container"""
    def __init__(self, command, version=RIP_VERSION):
        self.command = command
        self.version = version
        self.entries = []
    
    def add_entry(self, entry):
        """Add a routing entry (max 25 per message)"""
        if len(self.entries) < 25:
            self.entries.append(entry)
            return True
        return False
    
    def to_bytes(self):
        """Convert message to wire format"""
        # Header: command(1) + version(1) + zero(2)
        header = struct.pack('!BBH', self.command, self.version, 0)
        
        # Entries
        entries_bytes = b''.join(entry.to_bytes() for entry in self.entries)
        
        return header + entries_bytes
    
    @staticmethod
    def from_bytes(data):
        """Parse RIP message from bytes"""
        if len(data) < 4:
            return None
        
        command, version, _ = struct.unpack('!BBH', data[:4])
        
        msg = RIPMessage(command, version)
        
        # Parse entries
        offset = 4
        while offset + 20 <= len(data):
            entry = RIPEntry.from_bytes(data[offset:offset+20])
            if entry:
                msg.add_entry(entry)
            offset += 20
        
        return msg


class RIPProtocol:
    """Main RIP-2 Protocol Handler"""
    
    def __init__(self, node_id, network_interface):
        self.node_id = node_id
        self.network = network_interface
        
        # Routing table: destination -> RIPEntry
        self.routing_table = {}
        self.table_lock = threading.Lock()
        
        # Timers
        self.update_timer = None
        self.running = False
        
        # Triggered update control
        self.triggered_update_pending = False
        self.last_triggered_update = 0
        
    def start(self):
        """Start RIP protocol"""
        self.running = True
        
        # Start periodic update timer
        self._schedule_update()
        
        # Start message processing thread
        self.processing_thread = threading.Thread(target=self._process_messages, daemon=True)
        self.processing_thread.start()
        
        # Start garbage collection thread
        self.gc_thread = threading.Thread(target=self._garbage_collection_loop, daemon=True)
        self.gc_thread.start()
        
        print(f"[RIP] Protocol started for node {self.node_id}")
    
    def stop(self):
        """Stop RIP protocol"""
        self.running = False
        if self.update_timer:
            self.update_timer.cancel()
    
    def add_directly_connected_network(self, destination, subnet_mask, metric=DEFAULT_METRIC):
        """Add a directly connected network to routing table"""
        with self.table_lock:
            entry = RIPEntry(destination, subnet_mask, "0.0.0.0", metric)
            self.routing_table[destination] = entry
            print(f"[RIP] Added directly connected network: {destination}/{subnet_mask}")
    
    def get_routing_table(self):
        """Get a copy of the routing table"""
        with self.table_lock:
            return dict(self.routing_table)
    
    def _schedule_update(self):
        """Schedule next periodic update with random jitter"""
        if not self.running:
            return
        
        # Add random jitter (0-5 seconds) to prevent synchronization
        jitter = random.uniform(0, 5)
        interval = UPDATE_INTERVAL + jitter
        
        self.update_timer = threading.Timer(interval, self._send_periodic_update)
        self.update_timer.daemon = True
        self.update_timer.start()
    
    def _send_periodic_update(self):
        """Send periodic routing update"""
        self._send_update(triggered=False)
        self._schedule_update()
    
    def _send_update(self, triggered=False):
        """
        Send routing update
        Args:
            triggered: True if this is a triggered update
        """
        with self.table_lock:
            entries_to_send = []
            
            for dest, entry in self.routing_table.items():
                # For triggered updates, only send changed routes
                if triggered and not entry.changed:
                    continue
                
                # Apply split horizon with poisoned reverse
                send_entry = RIPEntry(
                    entry.destination,
                    entry.subnet_mask,
                    entry.next_hop,
                    entry.metric,
                    entry.route_tag
                )
                
                entries_to_send.append(send_entry)
            
            # Clear change flags
            if triggered:
                for entry in self.routing_table.values():
                    entry.changed = False
        
        # Send messages (max 25 entries per message)
        while entries_to_send:
            msg = RIPMessage(RESPONSE, RIP_VERSION)
            
            # Add up to 25 entries
            for _ in range(min(25, len(entries_to_send))):
                msg.add_entry(entries_to_send.pop(0))
            
            # Send message
            self.network.send_message(msg.to_bytes())
        
        update_type = "triggered" if triggered else "periodic"
        print(f"[RIP] Sent {update_type} update")
    
    def trigger_update(self):
        """Trigger an update with rate limiting"""
        current_time = time.time()
        
        # Rate limit: minimum 1 second between triggered updates
        if current_time - self.last_triggered_update < 1:
            self.triggered_update_pending = True
            return
        
        self.last_triggered_update = current_time
        self.triggered_update_pending = False
        
        # Schedule triggered update with random delay (1-5 seconds)
        delay = random.uniform(1, 5)
        timer = threading.Timer(delay, lambda: self._send_update(triggered=True))
        timer.daemon = True
        timer.start()
    
    def _process_messages(self):
        """Process incoming RIP messages"""
        while self.running:
            # Receive message with timeout
            msg_data = self.network.receive_message(timeout=1)
            
            if msg_data is None:
                continue
            
            data = msg_data['data']
            source = msg_data['source']
            rssi = msg_data['rssi']
            
            # Parse RIP message
            rip_msg = RIPMessage.from_bytes(data)
            
            if rip_msg is None:
                continue
            
            # Process based on command type
            if rip_msg.command == REQUEST:
                self._handle_request(rip_msg, source)
            elif rip_msg.command == RESPONSE:
                self._handle_response(rip_msg, source, rssi)
    
    def _handle_request(self, msg, source):
        """Handle RIP request message"""
        # Check for special case: request for entire routing table
        if len(msg.entries) == 1:
            entry = msg.entries[0]
            if entry.destination == "0.0.0.0" and entry.metric == INFINITY:
                # Send entire routing table
                self._send_update(triggered=False)
                return
        
        # Otherwise, respond with specific entries
        response = RIPMessage(RESPONSE, RIP_VERSION)
        
        with self.table_lock:
            for req_entry in msg.entries:
                if req_entry.destination in self.routing_table:
                    entry = self.routing_table[req_entry.destination]
                    response.add_entry(entry)
                else:
                    # Send infinity metric for unknown routes
                    unknown = RIPEntry(
                        req_entry.destination,
                        "255.255.255.0",
                        "0.0.0.0",
                        INFINITY
                    )
                    response.add_entry(unknown)
        
        self.network.send_message(response.to_bytes())
    
    def _handle_response(self, msg, source, rssi):
        """Handle RIP response message"""
        updated = False
        
        with self.table_lock:
            for entry in msg.entries:
                # Validate entry
                if not self._validate_entry(entry):
                    continue
                
                # Add cost of receiving network (using RSSI as proxy)
                # For simplicity, we use a fixed cost of 1
                new_metric = min(entry.metric + 1, INFINITY)
                
                dest = entry.destination
                
                # Check if route exists
                if dest in self.routing_table:
                    existing = self.routing_table[dest]
                    
                    # If from same source, always update
                    if existing.next_hop == source or entry.next_hop == source:
                        if existing.metric != new_metric:
                            existing.metric = new_metric
                            existing.timeout = time.time()
                            existing.changed = True
                            updated = True
                            
                            # If metric is infinity, start deletion
                            if new_metric >= INFINITY:
                                existing.garbage_timer = time.time()
                    
                    # If better metric, update
                    elif new_metric < existing.metric:
                        existing.next_hop = source
                        existing.metric = new_metric
                        existing.subnet_mask = entry.subnet_mask
                        existing.timeout = time.time()
                        existing.changed = True
                        existing.garbage_timer = None
                        updated = True
                    
                    # If same metric and route is timing out, switch
                    elif new_metric == existing.metric:
                        time_since_update = time.time() - existing.timeout
                        if time_since_update > TIMEOUT / 2:
                            existing.next_hop = source
                            existing.timeout = time.time()
                
                else:
                    # New route
                    if new_metric < INFINITY:
                        new_entry = RIPEntry(
                            dest,
                            entry.subnet_mask,
                            source,
                            new_metric,
                            entry.route_tag
                        )
                        new_entry.changed = True
                        self.routing_table[dest] = new_entry
                        updated = True
        
        # Trigger update if changes occurred
        if updated:
            self.trigger_update()
    
    def _validate_entry(self, entry):
        """Validate a RIP entry"""
        # Check metric range
        if entry.metric < 1 or entry.metric > INFINITY:
            return False
        
        # Check destination is not 0.0.0.0 or 127.x.x.x
        if entry.destination == "0.0.0.0" or entry.destination.startswith("127."):
            return False
        
        return True
    
    def _garbage_collection_loop(self):
        """Periodically check for expired routes"""
        while self.running:
            time.sleep(10)  # Check every 10 seconds
            
            current_time = time.time()
            to_delete = []
            
            with self.table_lock:
                for dest, entry in self.routing_table.items():
                    # Check timeout
                    if current_time - entry.timeout > TIMEOUT:
                        if entry.metric < INFINITY:
                            # Mark as unreachable
                            entry.metric = INFINITY
                            entry.changed = True
                            entry.garbage_timer = current_time
                    
                    # Check garbage collection
                    if entry.garbage_timer is not None:
                        if current_time - entry.garbage_timer > GARBAGE_COLLECTION:
                            to_delete.append(dest)
                
                # Remove expired routes
                for dest in to_delete:
                    del self.routing_table[dest]
                    print(f"[RIP] Removed expired route: {dest}")