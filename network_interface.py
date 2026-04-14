"""
Network Interface Module
Handles WiFi Action Frame communication for RIP protocol
"""

import struct
import threading
import queue
from scapy.all import *

# Configuration
IFACE = "wlan1"
CUSTOM_BSSID = "aa:bb:cc:dd:ee:ff"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
CUSTOM_OUI = b'\x11\x22\x33'
RIP_PORT = 520

class NetworkInterface:
    def __init__(self, node_name):
        self.node_name = node_name
        self.rx_queue = queue.Queue()
        self.running = False
        self.rx_thread = None
        
    def get_rssi(self, packet):
        """Extract RSSI from Radiotap header"""
        try:
            if packet.haslayer(RadioTap):
                if 'dBm_AntSignal' in packet[RadioTap].fields:
                    return packet[RadioTap].dBm_AntSignal
                elif hasattr(packet[RadioTap], 'dBm_AntSignal'):
                    return packet[RadioTap].dBm_AntSignal
        except Exception:
            pass
        return None
    
    def rx_handler(self, packet):
        """Process received WiFi Action Frames"""
        # Filter: 802.11 Management (type=0) -> Action (subtype=13)
        if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 13:
            # Match BSSID
            if packet.addr3 and packet.addr3.lower() == CUSTOM_BSSID.lower():
                payload_bytes = bytes(packet[Dot11].payload)
                
                # Check for Vendor Specific Category and OUI
                if len(payload_bytes) >= 4 and payload_bytes[0] == 127 and payload_bytes[1:4] == CUSTOM_OUI:
                    message = payload_bytes[4:]
                    
                    # Ignore messages from ourselves
                    if self.node_name.encode() not in message:
                        rssi = self.get_rssi(packet)
                        source_mac = packet.addr2
                        
                        # Put message in queue for RIP processing
                        self.rx_queue.put({
                            'data': message,
                            'source': source_mac,
                            'rssi': rssi
                        })
    
    def start_receiver(self):
        """Start the packet receiver thread"""
        self.running = True
        self.rx_thread = threading.Thread(target=self._receiver_loop, daemon=True)
        self.rx_thread.start()
        print(f"[NetworkInterface] Receiver started on {IFACE}")
    
    def _receiver_loop(self):
        """Main receiver loop"""
        sniff(iface=IFACE, prn=self.rx_handler, store=0, stop_filter=lambda x: not self.running)
    
    def send_message(self, message):
        """
        Send a message via WiFi Action Frame
        Args:
            message: bytes to send
        """
        dot11 = Dot11(
            type=0, 
            subtype=13, 
            addr1=BROADCAST_MAC, 
            addr2=RandMAC(), 
            addr3=CUSTOM_BSSID
        )
        
        action_payload = b'\x7f' + CUSTOM_OUI + message
        packet = RadioTap() / dot11 / Raw(load=action_payload)
        
        sendp(packet, iface=IFACE, verbose=0)
    
    def receive_message(self, timeout=None):
        """
        Receive a message from the queue
        Returns: dict with 'data', 'source', 'rssi' or None if timeout
        """
        try:
            return self.rx_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def stop(self):
        """Stop the receiver"""
        self.running = False
        if self.rx_thread:
            self.rx_thread.join(timeout=2)