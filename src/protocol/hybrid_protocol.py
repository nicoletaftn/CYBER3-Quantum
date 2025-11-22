"""
Hybrid Quantum-Classical Secure Communication Protocol
Combines QKD (key generation) + PQC (authentication) + AES (encryption)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from qkd.bb84 import BB84Protocol
from pqc.ml_dsa_auth import MLDSAAuthenticator
from crypto.aes_cipher import AESCipher
import time


class HybridSecureChannel:
    """
    Implements hybrid quantum-classical secure communication
    
    Security features:
    - QKD for symmetric key generation (information-theoretic security)
    - PQC for authentication (quantum-resistant digital signatures)
    - AES-256-GCM for message encryption (with QKD keys)
    """
    
    def __init__(self, name):
        """
        Initialize hybrid secure channel
        
        Args:
            name: Name of this party (e.g., 'Alice' or 'Bob')
        """
        self.name = name
        self.peer_name = None
        
        self.qkd = None
        self.authenticator = MLDSAAuthenticator()
        self.cipher = None
        
        self.qkd_key = None
        self.own_public_key = None
        self.own_private_key = None
        self.peer_public_key = None
        
        self.is_authenticated = False
        self.is_ready = False
        
        print(f"✓ Hybrid channel initialized for {name}")
    
    def setup_authentication(self):
        """Generate PQC keypair for authentication"""
        print(f"\n[{self.name}] Setting up authentication...")
        self.own_public_key, self.own_private_key = self.authenticator.generate_keypair()
        return self.own_public_key
    
    def exchange_public_keys(self, peer_public_key, peer_name):
        """
        Exchange and verify public keys with peer
        
        Args:
            peer_public_key: Peer's ML-DSA-65 public key
            peer_name: Name of the peer
        """
        print(f"\n[{self.name}] Exchanging public keys with {peer_name}...")
        self.peer_public_key = peer_public_key
        self.peer_name = peer_name
        self.is_authenticated = True
        print(f"  ✓ Public key exchange complete")
    
    def establish_qkd_key(self, qkd_protocol=None, key_length=256):
        """
        Generate shared symmetric key via QKD
        
        Args:
            qkd_protocol: Existing BB84Protocol instance (for shared network)
            key_length: Desired key length in bits
        """
        print(f"\n[{self.name}] Establishing QKD session key...")
        
        if qkd_protocol is None:
            self.qkd = BB84Protocol(key_length=key_length)
            self.qkd_key = self.qkd.generate_key()
        else:
            self.qkd = qkd_protocol
            self.qkd_key = qkd_protocol.generate_key()
        
        self.cipher = AESCipher(key=self.qkd_key)
        self.is_ready = True
        
        print(f"  ✓ Secure channel established")
    
    def send_secure_message(self, message):
        """
        Send authenticated and encrypted message
        
        Args:
            message: Plain text message (str)
            
        Returns:
            dict: Secure message package
        """
        if not self.is_ready:
            raise RuntimeError("Channel not ready. Establish connection first.")
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        if self.cipher is None:
            raise RuntimeError("Cipher not initialized. Establish QKD session first.")
        encrypted = self.cipher.encrypt(message)
        encrypted_bytes = (
            encrypted['nonce'] + 
            encrypted['tag'] + 
            encrypted['ciphertext']
        )
        
        signature = self.authenticator.sign(encrypted_bytes)
        
        package = {
            'sender': self.name,
            'encrypted_message': encrypted_bytes.hex(),
            'signature': signature.hex(),
            'timestamp': time.time()
        }
        
        return package
    
    def receive_secure_message(self, package):
        """
        Receive, verify, and decrypt message
        
        Args:
            package: Secure message package from send_secure_message()
            
        Returns:
            str: Decrypted plaintext message
        """
        if not self.is_ready:
            raise RuntimeError("Channel not ready. Establish connection first.")
        
        encrypted_bytes = bytes.fromhex(package['encrypted_message'])
        signature = bytes.fromhex(package['signature'])
        sender = package['sender']
        
        is_valid = self.authenticator.verify(
            encrypted_bytes,
            signature,
            self.peer_public_key
        )
        
        if not is_valid:
            raise ValueError(f"Signature verification failed! Message from {sender} may be forged.")
        
        if self.cipher is None:
            raise RuntimeError("Cipher not initialized. Establish QKD session first.")
        plaintext = self.cipher.decrypt_message(encrypted_bytes)
        return plaintext.decode('utf-8')
    
    def get_status(self):
        """Get channel status information"""
        return {
            'name': self.name,
            'peer': self.peer_name,
            'authenticated': self.is_authenticated,
            'ready': self.is_ready,
            'qkd_key_length': len(self.qkd_key) if self.qkd_key else None,
            'security': {
                'key_generation': 'QKD (BB84)',
                'authentication': 'ML-DSA-65 (NIST FIPS 204)',
                'encryption': 'AES-256-GCM'
            }
        }
    
    def cleanup(self):
        """Cleanup resources"""
        if self.qkd:
            self.qkd.cleanup()