"""
Secure Terminal Interface with Network Support
Interactive CLI for hybrid quantum-classical secure communication
"""

import os
liboqs_lib_path = "/opt/homebrew/opt/liboqs/lib"
if os.path.exists(liboqs_lib_path):
    current_path = os.environ.get('DYLD_LIBRARY_PATH', '')
    if liboqs_lib_path not in current_path:
        os.environ['DYLD_LIBRARY_PATH'] = f"{liboqs_lib_path}:{current_path}"

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from protocol.hybrid_protocol import HybridSecureChannel
from qkd.bb84 import BB84Protocol
from network.socket_comm import NetworkChannel
from crypto.aes_cipher import AESCipher
import argparse


class SecureTerminal:
    """Interactive terminal for secure communication with network support"""
    
    def __init__(self, name, role, peer_name, host='localhost', port=9999):
        """
        Initialize secure terminal
        
        Args:
            name: Name of this terminal (Alice or Bob)
            role: 'server' or 'client'
            peer_name: Name of the peer
            host: Network host
            port: Network port
        """
        self.name = name
        self.role = role
        self.peer_name = peer_name
        self.channel = HybridSecureChannel(name)
        self.network = NetworkChannel(role, host, port)
        self.running = False
        self.message_count = 0
        self.received_messages = []
        
    def setup_network(self):
        """Establish network connection"""
        if self.role == 'server':
            success = self.network.start_server()
        else:
            success = self.network.connect_to_server()
        
        if success:
            print("✓ Network layer ready\n")
        
        return success
    
    def setup_secure_channel(self):
        """Setup the complete secure channel"""
        print("=" * 60)
        print(f"  HYBRID QUANTUM-CLASSICAL SECURE TERMINAL")
        print("=" * 60)
        print(f"Terminal: {self.name} ({self.role.upper()})")
        print(f"Peer: {self.peer_name}")
        print("=" * 60)
        
        print("\n[1/4] Setting up authentication...")
        own_public_key = self.channel.setup_authentication()
        
        print("\n[2/4] Exchanging public keys...")
        if self.role == 'server':
            self.network.send_data({
                'type': 'public_key',
                'public_key': own_public_key.hex(),
                'name': self.name
            })
            peer_key_msg = self.network.receive_data()
        else:
            peer_key_msg = self.network.receive_data()
            self.network.send_data({
                'type': 'public_key',
                'public_key': own_public_key.hex(),
                'name': self.name
            })

        if peer_key_msg and peer_key_msg['type'] == 'public_key':
            peer_public_key = bytes.fromhex(peer_key_msg['public_key'])
            self.channel.exchange_public_keys(peer_public_key, peer_key_msg['name'])
        else:
            raise Exception("Failed to receive peer's public key")
        
        print("\n[3/4] Quantum Key Distribution...")
        if self.role == 'server':
            qkd_protocol = BB84Protocol(key_length=128)
            self.channel.establish_qkd_key(qkd_protocol)
            self.network.send_data({
                'type': 'qkd_key',
                'key': self.channel.qkd_key.hex()
            })
        else:
            qkd_msg = self.network.receive_data()
            if qkd_msg and qkd_msg['type'] == 'qkd_key':
                self.channel.qkd_key = bytes.fromhex(qkd_msg['key'])
                self.channel.cipher = AESCipher(key=self.channel.qkd_key)
                self.channel.is_ready = True
                print(f"  ✓ Received QKD key")
            else:
                raise Exception("Failed to receive QKD key")
        
        print("\n[4/4] Secure channel established!")
        self.network.start_listening(self._handle_incoming_message)
        self.show_status()
    
    def _handle_incoming_message(self, data):
        """Handle incoming network messages"""
        if data['type'] == 'secure_message':
            package = {
                'sender': data['sender'],
                'encrypted_message': data['encrypted_message'],
                'signature': data['signature'],
                'timestamp': data['timestamp']
            }
            
            try:
                plaintext = self.channel.receive_secure_message(package)
                print(f"\n[{data['sender']} → {self.name}]: {plaintext}")
                print(f"{self.name}> ", end="", flush=True)
                
                self.received_messages.append({
                    'from': data['sender'],
                    'message': plaintext,
                    'timestamp': data['timestamp']
                })
                
            except Exception as e:
                print(f"\n✗ Error: {e}")
                print(f"{self.name}> ", end="", flush=True)
    
    def send_message(self, message):
        """Send a secure message over the network"""
        if not self.channel.is_ready:
            print("✗ Error: Channel not established")
            return False
        
        try:
            package = self.channel.send_secure_message(message)
            self.network.send_data({
                'type': 'secure_message',
                'sender': package['sender'],
                'encrypted_message': package['encrypted_message'],
                'signature': package['signature'],
                'timestamp': package['timestamp']
            })
            
            self.message_count += 1
            return True
            
        except Exception as e:
            print(f"✗ Error: {e}")
            return False
    
    def show_status(self):
        """Display channel status"""
        print("\n" + "=" * 60)
        print("  CONNECTION STATUS")
        print("=" * 60)
        
        status = self.channel.get_status()
        
        print(f"Terminal:          {status['name']} ({self.role})")
        print(f"Peer:              {status['peer']}")
        print(f"Network:           {'✓ Connected' if self.network.connected else '✗ Disconnected'}")
        print(f"Authenticated:     {'✓ Yes' if status['authenticated'] else '✗ No'}")
        print(f"Ready:             {'✓ Yes' if status['ready'] else '✗ No'}")
        if status['qkd_key_length']:
            print(f"QKD Key:           {status['qkd_key_length']} bytes")
        print(f"Messages Sent:     {self.message_count}")
        print(f"Messages Received: {len(self.received_messages)}")
        
        print("\nSecurity Stack:")
        for key, value in status['security'].items():
            print(f"  • {key.replace('_', ' ').title()}: {value}")
        print("=" * 60)
    
    def interactive_mode(self):
        """Run interactive terminal"""
        print("\n" + "=" * 60)
        print("  Ready to communicate!")
        print("=" * 60)
        print("Commands: <message> | /status | /history | /help | /quit")
        print("=" * 60)
        
        self.running = True
        
        while self.running:
            try:
                user_input = input(f"\n{self.name}> ").strip()
                
                if not user_input:
                    continue
                
                if user_input == '/status':
                    self.show_status()
                
                elif user_input == '/history':
                    print("\n" + "=" * 60)
                    print("  MESSAGE HISTORY")
                    print("=" * 60)
                    if self.received_messages:
                        for msg in self.received_messages:
                            print(f"  [{msg['from']}]: {msg['message']}")
                    else:
                        print("  No messages received yet")
                    print("=" * 60)
                
                elif user_input == '/help':
                    print("\nCommands:")
                    print("  <message>  - Send encrypted message")
                    print("  /status    - Show connection status")
                    print("  /history   - Show message history")
                    print("  /help      - Show this help")
                    print("  /quit      - Exit terminal")
                
                elif user_input == '/quit':
                    print("\nShutting down...")
                    self.running = False
                
                elif user_input.startswith('/'):
                    print(f"✗ Unknown command. Type /help for commands")
                
                else:
                    self.send_message(user_input)
                    
            except KeyboardInterrupt:
                print("\n\nShutting down...")
                self.running = False
            except EOFError:
                self.running = False
    
    def cleanup(self):
        """Cleanup resources"""
        self.network.close()
        self.channel.cleanup()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Hybrid Quantum-Classical Secure Terminal',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Terminal 1 (Alice - Server):
    python secure_terminal.py --name Alice --role server --peer Bob
  
  Terminal 2 (Bob - Client):
    python secure_terminal.py --name Bob --role client --peer Alice
        """
    )
    
    parser.add_argument('--name', required=True, type=str,
                       help='Your terminal name (e.g., Alice or Bob)')
    parser.add_argument('--role', required=True, choices=['server', 'client'],
                       help='Network role: server (waits) or client (connects)')
    parser.add_argument('--peer', required=True, type=str,
                       help='Peer terminal name')
    parser.add_argument('--host', default='localhost', type=str,
                       help='Host address (default: localhost)')
    parser.add_argument('--port', default=9999, type=int,
                       help='Port number (default: 9999)')
    
    args = parser.parse_args()
    
    try:
        terminal = SecureTerminal(args.name, args.role, args.peer, args.host, args.port)
        
        if not terminal.setup_network():
            print("✗ Failed to establish network connection")
            return
        
        terminal.setup_secure_channel()
        terminal.interactive_mode()
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
    
    finally:
        if 'terminal' in locals():
            terminal.cleanup()


if __name__ == "__main__":
    main()