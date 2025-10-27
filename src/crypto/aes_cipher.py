"""
AES-256 Symmetric Encryption
Uses keys derived from QKD for encryption/decryption
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib


class AESCipher:
    """AES-256 encryption in GCM mode (authenticated encryption)"""
    
    def __init__(self, key=None):
        """
        Initialize AES cipher
        
        Args:
            key: 256-bit (32 bytes) encryption key. If None, generates random key.
        """
        if key is None:
            self.key = get_random_bytes(32)
        else:
            if len(key) < 32:
                self.key = hashlib.sha256(key).digest()
            elif len(key) > 32:
                self.key = key[:32]
            else:
                self.key = key
        
    def encrypt(self, plaintext):
        """
        Encrypt plaintext using AES-256-GCM
        
        Args:
            plaintext: Data to encrypt (bytes or str)
            
        Returns:
            dict: Contains 'ciphertext', 'nonce', and 'tag'
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        return {
            'ciphertext': ciphertext,
            'nonce': cipher.nonce,
            'tag': tag
        }
    
    def decrypt(self, encrypted_data):
        """
        Decrypt ciphertext using AES-256-GCM
        
        Args:
            encrypted_data: Dict with 'ciphertext', 'nonce', and 'tag'
            
        Returns:
            bytes: Decrypted plaintext
        """
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=encrypted_data['nonce'])
        
        try:
            plaintext = cipher.decrypt_and_verify(
                encrypted_data['ciphertext'],
                encrypted_data['tag']
            )
            return plaintext
        except ValueError as e:
            raise ValueError("Authentication failed - message may be tampered") from e
    
    def encrypt_message(self, message):
        """
        Convenience method: encrypt and return serialized format
        
        Args:
            message: String or bytes to encrypt
            
        Returns:
            bytes: Nonce + Tag + Ciphertext (concatenated)
        """
        encrypted = self.encrypt(message)
        return encrypted['nonce'] + encrypted['tag'] + encrypted['ciphertext']
    
    def decrypt_message(self, encrypted_message):
        """
        Convenience method: decrypt from serialized format
        
        Args:
            encrypted_message: bytes from encrypt_message()
            
        Returns:
            bytes: Decrypted plaintext
        """
        nonce = encrypted_message[:16]
        tag = encrypted_message[16:32]
        ciphertext = encrypted_message[32:]
        
        encrypted_data = {
            'nonce': nonce,
            'tag': tag,
            'ciphertext': ciphertext
        }
        
        return self.decrypt(encrypted_data)
    
    def get_key_info(self):
        """Get information about the encryption key"""
        return {
            'algorithm': 'AES-256-GCM',
            'key_length': len(self.key) * 8,
            'mode': 'GCM (Galois/Counter Mode)',
            'features': 'Authenticated Encryption with Associated Data (AEAD)'
        }