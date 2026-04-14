"""
RIP Protocol Command Line Interface
"""

import cmd
import threading

class RIPCLI(cmd.Cmd):
    """Interactive CLI for RIP protocol"""
    
    intro = 'Welcome to RIP-2 CLI. Type help or ? to list commands.\n'
    prompt = '(rip) '
    
    def __init__(self, rip_protocol):
        super().__init__()
        self.rip = rip_protocol
        self.show_logs = True
        
    def do_show_routes(self, arg):
        """Show current routing table"""
        table = self.rip.get_routing_table()
        
        if not table:
            print("Routing table is empty")
            return
        
        print("\n" + "="*80)
        print(f"{'Destination':<18} {'Mask':<18} {'Next Hop':<18} {'Metric':<8} {'Tag':<6}")
        print("="*80)
        
        for dest, entry in sorted(table.items()):
            print(f"{entry.destination:<18} {entry.subnet_mask:<18} "
                  f"{entry.next_hop:<18} {entry.metric:<8} {entry.route_tag:<6}")
        
        print("="*80 + "\n")
    
    def do_show_route(self, arg):
        """Show details for a specific route: show_route <destination>"""
        if not arg:
            print("Usage: show_route <destination>")
            return
        
        table = self.rip.get_routing_table()
        
        if arg not in table:
            print(f"Route {arg} not found")
            return
        
        entry = table[arg]
        print(f"\nRoute Details for {arg}:")
        print(f"  Destination: {entry.destination}")
        print(f"  Subnet Mask: {entry.subnet_mask}")
        print(f"  Next Hop: {entry.next_hop}")
        print(f"  Metric: {entry.metric}")
        print(f"  Route Tag: {entry.route_tag}")
        print(f"  Last Update: {entry.timeout}")
        print(f"  Changed: {entry.changed}")
        print()
    
    def do_send_request(self, arg):
        """Send RIP request for entire routing table"""
        from rip_protocol import RIPMessage, RIPEntry, REQUEST, INFINITY
        
        msg = RIPMessage(REQUEST)
        # Special request for entire table
        entry = RIPEntry("0.0.0.0", "0.0.0.0", "0.0.0.0", INFINITY)
        msg.add_entry(entry)
        
        self.rip.network.send_message(msg.to_bytes())
        print("Request sent")
    
    def do_trigger_update(self, arg):
        """Manually trigger a routing update"""
        self.rip.trigger_update()
        print("Triggered update scheduled")
    
    def do_add_network(self, arg):
        """Add a directly connected network: add_network <dest> <mask> [metric]"""
        parts = arg.split()
        
        if len(parts) < 2:
            print("Usage: add_network <destination> <subnet_mask> [metric]")
            return
        
        dest = parts[0]
        mask = parts[1]
        metric = int(parts[2]) if len(parts) > 2 else 1
        
        self.rip.add_directly_connected_network(dest, mask, metric)
        print(f"Added network {dest}/{mask} with metric {metric}")
    
    def do_logs(self, arg):
        """Toggle log display: logs [on|off]"""
        if arg.lower() == 'on':
            self.show_logs = True
            print("Logs enabled")
        elif arg.lower() == 'off':
            self.show_logs = False
            print("Logs disabled")
        else:
            status = "enabled" if self.show_logs else "disabled"
            print(f"Logs are currently {status}")
    
    def do_stats(self, arg):
        """Show protocol statistics"""
        table = self.rip.get_routing_table()
        
        total_routes = len(table)
        direct_routes = sum(1 for e in table.values() if e.next_hop == "0.0.0.0")
        unreachable = sum(1 for e in table.values() if e.metric >= 16)
        
        print(f"\nRIP Statistics:")
        print(f"  Total routes: {total_routes}")
        print(f"  Direct routes: {direct_routes}")
        print(f"  Unreachable routes: {unreachable}")
        print(f"  Node ID: {self.rip.node_id}")
        print()
    
    def do_clear(self, arg):
        """Clear the screen"""
        import os
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def do_exit(self, arg):
        """Exit the CLI"""
        print("Shutting down...")
        return True
    
    def do_quit(self, arg):
        """Quit the CLI"""
        return self.do_exit(arg)