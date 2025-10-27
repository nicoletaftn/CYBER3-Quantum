"""
Post-Quantum Authentication using ML-DSA-65 (formerly Dilithium3)
Provides digital signatures resistant to quantum attacks
"""

import oqs
import os

liboqs_lib_path = "/opt/homebrew/opt/liboqs/lib"
if os.path.exists(liboqs_lib_path):
    os.environ['DYLD_LIBRARY_PATH'] = f"{liboqs_lib_path}:{os.environ.get('DYLD_LIBRARY_PATH', '')}"


class MLDSAAuthenticator:
    """ML-DSA-65 (NIST FIPS 204) digital signature scheme"""
    
    def __init__(self):
        """Initialize ML-DSA-65 signature scheme"""
        self.algorithm = "ML-DSA-65"
        self.signer = oqs.Signature(self.algorithm)
        self.public_key = None
        self.private_key = None
        
    def generate_keypair(self):
        """
        Generate new ML-DSA-65 keypair
        
        Returns:
            tuple: (public_key, private_key) as bytes
        """
        self.public_key = self.signer.generate_keypair()
        self.private_key = self.signer.export_secret_key()
        print(f"✓ ML-DSA-65 keypair generated")
        
        return self.public_key, self.private_key
    
    def sign(self, message):
        """
        Sign a message with private key
        
        Args:
            message: Message to sign (bytes or str)
            
        Returns:
            bytes: Digital signature
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        if self.private_key is None:
            raise ValueError("No private key available. Generate keypair first.")
        
        signature = self.signer.sign(message)
        return signature
    
    def verify(self, message, signature, public_key=None):
        """
        Verify a signature
        
        Args:
            message: Original message (bytes or str)
            signature: Signature to verify (bytes)
            public_key: Public key to use (optional, uses own if not provided)
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        key_to_use = public_key if public_key is not None else self.public_key
        
        if key_to_use is None:
            raise ValueError("No public key available")
        
        try:
            is_valid = self.signer.verify(message, signature, key_to_use)
            return is_valid
        except Exception:
            return False
    
    def export_public_key(self):
        """Export public key for sharing"""
        if self.public_key is None:
            raise ValueError("No public key available. Generate keypair first.")
        return self.public_key
    
    def import_public_key(self, public_key):
        """Import a public key from another party"""
        self.public_key = public_key
        return True
    
    def get_details(self):
        """Get algorithm details"""
        return {
            'algorithm': self.algorithm,
            'public_key_length': len(self.public_key) if self.public_key else None,
            'signature_length': self.signer.details['length_signature'],
            'security_level': 'NIST Level 3 (AES-192 equivalent)'
        }