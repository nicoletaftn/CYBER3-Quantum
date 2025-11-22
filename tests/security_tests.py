import unittest
import time
import os
import sys
# Make sure `src` (the package root) is on sys.path so tests can import project modules
# when running this file directly or when the working directory is the repository root.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.protocol.hybrid_protocol import HybridSecureChannel
from src.crypto.aes_cipher import AESCipher
from src.qkd.bb84 import BB84Protocol
from src.pqc.ml_dsa_auth import MLDSAAuthenticator

class TestSecurityScenarios(unittest.TestCase):

    def setUp(self):
        # Setup test environment before each test
        
        print("\n" + "="*50)
        
        # Initialize channels for Alice and Bob
        self.alice = HybridSecureChannel("Alice")
        self.bob = HybridSecureChannel("Bob")
        
        # Setup PQC Authentication
        self.alice_pub = self.alice.setup_authentication()
        self.bob_pub = self.bob.setup_authentication()
        
        # Exchange keys (Normal operation)
        self.alice.exchange_public_keys(self.bob_pub, "Bob")
        self.bob.exchange_public_keys(self.alice_pub, "Alice")
        
        # Manually set a shared QKD key for testing, and also for speed
        shared_key = b'0'*32 # 256-bit key of all zeros
        self.alice.qkd_key = shared_key
        self.bob.qkd_key = shared_key
        
        self.alice.cipher = AESCipher(self.alice.qkd_key)
        self.bob.cipher = AESCipher(self.bob.qkd_key)
        
        self.alice.is_ready = True
        self.bob.is_ready = True
        
        print("\n" + "-"*50)

    # TEST 1: Man-in-the-Middle (MITM) - Signature Forgery
    def test_signature_forgery(self):
        # Scenario: An attacker (Mallory) intercepts a message and tries to 
        # send her own message to Bob pretending to be Alice.
        print("TEST: Signature Forgery / MITM Attack")
        
        # 1. Mallory generates her own keys
        mallory_auth = MLDSAAuthenticator()
        mallory_auth.generate_keypair()
        
        # 2. Mallory creates a fake message
        fake_msg = b"Transfer $1M to Mallory"
        
        # 3. Mallory encrypts it (assuming she somehow got the key, or just sends garbage)
        # Even if she encrypts it validly, the signature check comes first.
        if self.alice.cipher is None:
            raise ValueError("Alice's cipher is not initialized.")
        encrypted = self.alice.cipher.encrypt(fake_msg) # Mallory uses Alice's cipher for simulation
        encrypted_bytes = encrypted['nonce'] + encrypted['tag'] + encrypted['ciphertext']
        
        # 4. Mallory signs it with HER private key (not Alice's)
        forged_signature = mallory_auth.sign(encrypted_bytes)
        
        # 5. Construct the package sent to Bob
        forged_package = {
            'sender': 'Alice', # Pretending to be Alice
            'encrypted_message': encrypted_bytes.hex(),
            'signature': forged_signature.hex(),
            'timestamp': time.time()
        }
        
        # 6. Bob receives the message
        # EXPECTATION: Verification should fail because Bob checks against Alice's public key
        with self.assertRaises(ValueError) as context:
            self.bob.receive_secure_message(forged_package)
            
        print(f"  ✓ System correctly rejected forgery: {context.exception}")

    # TEST 2: Integrity Attack - Message Tampering
    def test_message_tampering(self):
        # Scenario: Attacker intercepts a valid packet and modifies the ciphertext 
        # (flipping a bit) to corrupt the data.
        print("TEST: Message Tampering (Integrity Check)")
        
        # 1. Alice sends a valid message
        original_msg = "Meet at dawn"
        package = self.alice.send_secure_message(original_msg)
        
        # 2. Attacker Intercepts and Modifies Ciphertext
        # Get the hex string
        hex_str = package['encrypted_message']
        # Flip the last character of the hex string (modifying the last byte)
        modified_hex = hex_str[:-1] + ('0' if hex_str[-1] != '0' else '1')
        
        package['encrypted_message'] = modified_hex
        
        # 3. Recalculate signature so PQC doesn't catch it 
        # (Assuming attacker simply modifies the payload but can't sign it validly)
        # If we don't update signature, PQC fails. 
        # If we update signature (assuming attacker stole Alice's key?), AES-GCM fails.
        # This is because the tag will not match the modified ciphertext. 
        # The Galois/Counter Mode (GCM) in AES-256 uses an authentication tag (tag). 
        # This tag is mathematically linked to the original ciphertext and the symmetric key.
        
        # Let's assume the attacker modifies it in transit.
        # PQC verification will fail first because the signed data (encrypted_bytes) changed 
        # but the signature didn't.
        with self.assertRaises(ValueError) as context:
            self.bob.receive_secure_message(package)
        print(f"  ✓ PQC rejected tampered payload: {context.exception}")

    # TEST 3: AES-GCM Tag Validation (Deep Cipher Test)
    def test_aes_gcm_integrity(self):
        # Scenario: Verify that AES-GCM specifically detects tampering even if 
        # signature checks were bypassed.
        print("TEST: AES-GCM Tag Validation")
    
        cipher = AESCipher(key=b'secret'*6 + b'12') # 32 bytes
        data = b"Top Secret Data"
        
        # Encryption (Alice's side)
        encrypted = cipher.encrypt(data)
        
        # Show the original tag and ciphertext that will be verified
        print(f"  - Original Tag (Alice created):   {encrypted['tag'].hex()}")
        print(f"  - Original Ciphertext:            {encrypted['ciphertext'].hex()}")
        
        # Tampering (Attacker's side) - THIS LINE MUST BE ACTIVE
        ciphertext_list = list(encrypted['ciphertext'])
        # Flip all bits in the first byte to cause corruption
        ciphertext_list[0] = ciphertext_list[0] ^ 0xFF 
        encrypted['ciphertext'] = bytes(ciphertext_list)
        
        # Show the tampered ciphertext with the same original tag
        print(f"  - Tampered Ciphertext:            {encrypted['ciphertext'].hex()}")
        
        # Decryption (Bob's side)
        # Expectation: Decryption fails because the tag no longer matches the tampered ciphertext.
        with self.assertRaises(ValueError) as context:
            cipher.decrypt(encrypted) 
            
        self.assertIn("Authentication failed", str(context.exception))
        print(f"  ✓ AES-GCM correctly detected tampering: {context.exception}")

    # TEST 4: Quantum Eavesdropping Detection
    def test_qkd_eavesdropping(self):
        # Scenario: Simulate a high error rate (Intercept-Resend Attack) 
        # and verify the protocol detects it.
        print("TEST: QKD Eavesdropping Detection")
        
        bb84 = BB84Protocol(key_length=128)
        
        # Simulate 100 bits
        # Alice has random bits
        alice_bits = [1] * 50 + [0] * 50
        
        # Bob has bits that match Alice's (Normal case)
        bob_bits_clean = [1] * 50 + [0] * 50
        
        # Bob has bits with 25% error rate (Eavesdropping case)
        # We flip 25 of the bits
        bob_bits_noisy = bob_bits_clean.copy()
        for i in range(25):
            bob_bits_noisy[i] = 1 - bob_bits_noisy[i] # Flip bit
            
        # Check Clean Error Rate
        error_clean = bb84._check_errors(alice_bits, bob_bits_clean)
        self.assertEqual(error_clean, 0.0, "Clean channel should have 0% error")
        
        # Check Noisy Error Rate
        error_noisy = bb84._check_errors(alice_bits, bob_bits_noisy)
        
        print(f"  - Simulated Error Rate: {error_noisy:.1%}")
        
        # Assert that high error rate is detected (> 15%)
        self.assertTrue(error_noisy > 0.15, "System failed to detect high error rate!")
        print("  ✓ Eavesdropper detection threshold triggered")

if __name__ == '__main__':
    unittest.main()