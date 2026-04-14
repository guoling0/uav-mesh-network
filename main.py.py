#!/usr/bin/env python3
"""
RIP-2 Protocol Implementation - Main Entry Point
Usage: sudo python3 main.py <NODE_NAME>
"""

import sys
import signal
import time
from network_interface import NetworkInterface
from rip_protocol import RIPProtocol
from rip_cli import RIPCLI

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[*] Shutting down...")
    sys.exit(0)

def main():
    if len(sys.argv) != 2:
        print("Usage: sudo python3 main.py <NODE_NAME>")
        sys.exit(1)
    
    node_name = sys.argv[1]
    
    print(f"[*] Starting RIP-2 Protocol for node: {node_name}")
    
    # Initialize network interface
    network = NetworkInterface(node_name)
    network.start_receiver()
    
    # Give receiver time to start
    time.sleep(1)
    
    # Initialize RIP protocol
    rip = RIPProtocol(node_name, network)
    
    # Example: Add some directly connected networks
    # You can modify these based on your actual network configuration
    # rip.add_directly_connected_network("192.168.1.0", "255.255.255.0", 1)
    
    # Start RIP protocol
    rip.start()
    
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    print(f"[*] RIP-2 protocol running. Node: {node_name}")
    print(f"[*] Enter 'show_routes' to see routing table")
    print(f"[*] Enter 'help' for all commands")
    print()
    
    # Start CLI
    cli = RIPCLI(rip)
    try:
        cli.cmdloop()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        rip.stop()
        network.stop()

if __name__ == "__main__":
    main()