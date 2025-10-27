"""
Simple Socket-based Network Communication
For transmitting encrypted messages between terminals
"""

import socket
import json
import threading
import time


class NetworkChannel:
    """Socket-based network communication for secure terminals"""
    
    def __init__(self, role, host='localhost', port=9999):
        """
        Initialize network channel
        
        Args:
            role: 'server' or 'client'
            host: Hostname to connect/bind to
            port: Port number
        """
        self.role = role
        self.host = host
        self.port = port
        self.socket = None
        self.connection = None
        self.connected = False
        self.running = False
        self.receive_callback = None
        
    def start_server(self):
        """Start as server (waits for connection)"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(1)
            
            print(f"✓ Server listening on {self.host}:{self.port}")
            print(f"  Waiting for peer to connect...")
            
            self.connection, addr = self.socket.accept()
            self.connected = True
            print(f"✓ Peer connected from {addr}")
            
            return True
            
        except Exception as e:
            print(f"✗ Server error: {e}")
            return False
    
    def connect_to_server(self, timeout=30):
        """Connect as client"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"Connecting to {self.host}:{self.port}...")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                self.socket.connect((self.host, self.port))
                self.connection = self.socket
                self.connected = True
                print(f"✓ Connected to server")
                return True
            except ConnectionRefusedError:
                print(".", end="", flush=True)
                time.sleep(1)
        
        print(f"\n✗ Connection timeout")
        return False
    
    def send_data(self, data):
        """
        Send data over the network
        
        Args:
            data: Dictionary to send (will be JSON serialized)
        """
        if not self.connected:
            raise RuntimeError("Not connected")
        
        try:
            json_data = json.dumps(data)
            message = json_data.encode('utf-8')
            length = len(message)
            
            self.connection.sendall(length.to_bytes(4, 'big'))
            self.connection.sendall(message)
            return True
            
        except Exception as e:
            print(f"✗ Send error: {e}")
            return False
    
    def receive_data(self):
        """
        Receive data from the network
        
        Returns:
            dict: Received data
        """
        if not self.connected:
            raise RuntimeError("Not connected")
        
        try:
            length_bytes = self._recv_exactly(4)
            if not length_bytes:
                return None
            
            length = int.from_bytes(length_bytes, 'big')
            message_bytes = self._recv_exactly(length)
            if not message_bytes:
                return None
            
            json_data = message_bytes.decode('utf-8')
            data = json.loads(json_data)
            return data
            
        except Exception as e:
            print(f"✗ Receive error: {e}")
            return None
    
    def _recv_exactly(self, n):
        """Receive exactly n bytes"""
        data = bytearray()
        while len(data) < n:
            packet = self.connection.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return bytes(data)
    
    def start_listening(self, callback):
        """
        Start background thread to listen for incoming messages
        
        Args:
            callback: Function to call when message received
        """
        self.receive_callback = callback
        self.running = True
        
        listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
        listen_thread.start()
    
    def _listen_loop(self):
        """Background listening loop"""
        while self.running and self.connected:
            try:
                data = self.receive_data()
                if data and self.receive_callback:
                    self.receive_callback(data)
            except Exception as e:
                if self.running:
                    print(f"\n✗ Listen error: {e}")
                break
    
    def close(self):
        """Close connection"""
        self.running = False
        self.connected = False
        
        if self.connection:
            try:
                self.connection.close()
            except:
                pass
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass