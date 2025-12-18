import unittest
import time
import os
import sys

# Make sure `src` (the package root) is on sys.path so tests can import project modules
# when running this file directly or when the working directory is the repository root.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.protocol.hybrid_protocol import HybridSecureChannel
from src.crypto.aes_cipher import AESCipher
from src.qkd.bb84 import BB84Protocol
from src.pqc.ml_dsa_auth import MLDSAAuthenticator


class TestSecurityScenarios(unittest.TestCase):

    def setUp(self):
        # Setup test environment before each test
        print("\n" + "=" * 60)
        print("SETUP: Initializing Hybrid Secure Channels")

        # Initialize channels for Alice and Bob
        self.alice = HybridSecureChannel("Alice")
        self.bob = HybridSecureChannel("Bob")

        # Setup PQC Authentication
        self.alice_pub = self.alice.setup_authentication()
        self.bob_pub = self.bob.setup_authentication()

        # Exchange keys (Normal operation)
        self.alice.exchange_public_keys(self.bob_pub, "Bob")
        self.bob.exchange_public_keys(self.alice_pub, "Alice")

        # Manually set a shared QKD key for testing speed
        shared_key = b"0" * 32  # 256-bit key of all zeros
        self.alice.qkd_key = shared_key
        self.bob.qkd_key = shared_key

        self.alice.cipher = AESCipher(self.alice.qkd_key)
        self.bob.cipher = AESCipher(self.bob.qkd_key)

        self.alice.is_ready = True
        self.bob.is_ready = True
        print("SETUP COMPLETE")
        print("-" * 60)

    # TEST 1: Man-in-the-Middle (MITM) - Signature Forgery
    def test_signature_forgery(self):
        # Scenario: An attacker (Mallory) intercepts a message and tries to
        # send her own message to Bob pretending to be Alice.
        print("\nTEST: Signature Forgery / MITM Attack")
        print("SCENARIO: Attacker 'Mallory' tries to impersonate 'Alice'.")

        # 1. Mallory generates her own keys
        print("\n[Step 1] Mallory generates her own malicious keypair...")
        mallory_auth = MLDSAAuthenticator()
        mallory_auth.generate_keypair()

        # 2. Mallory creates a fake message
        fake_msg = b"Transfer $1M to Mallory"
        print(f"[Step 2] Mallory creates a forged message: '{fake_msg.decode()}'")

        # 3. Mallory encrypts it (assuming she somehow got the key, or just sends garbage)
        # Even if she encrypts it validly, the signature check comes first.
        if self.alice.cipher is None:
            raise ValueError("Alice's cipher is not initialized.")

        print(
            "[Step 3] Mallory encrypts the message (using stolen/simulated cipher)..."
        )
        encrypted = self.alice.cipher.encrypt(fake_msg)
        encrypted_bytes = (
            encrypted["nonce"] + encrypted["tag"] + encrypted["ciphertext"]
        )

        # 4. Mallory signs it with HER private key (not Alice's)
        print(
            "[Step 4] Mallory signs the package with HER private key (since she lacks Alice's)."
        )
        forged_signature = mallory_auth.sign(encrypted_bytes)

        # 5. Construct the package sent to Bob
        forged_package = {
            "sender": "Alice",  # Pretending to be Alice
            "encrypted_message": encrypted_bytes.hex(),
            "signature": forged_signature.hex(),
            "timestamp": time.time(),
        }
        print(f"[Step 5] Sending forged package to Bob (Claiming sender is 'Alice')...")

        # 6. Bob receives the message
        # EXPECTATION: Verification should fail because Bob checks against Alice's public key
        print(
            "[Step 6] Bob receives message and verifies signature against Alice's known public key..."
        )
        with self.assertRaises(ValueError) as context:
            self.bob.receive_secure_message(forged_package)

        print(f"\nSUCCESS: System correctly rejected the forgery.")
        print(f'  Error Message Caught: "{context.exception}"')
        print(
            "  Reason: The signature was valid for Mallory's key, but Bob used Alice's key to verify."
        )

    # TEST 2: Integrity Attack - Message Tampering
    def test_message_tampering(self):
        # Scenario: Attacker intercepts a valid packet and modifies the ciphertext
        # (flipping a bit) to corrupt the data.
        print("\nTEST: Message Tampering (Integrity Check)")
        print("SCENARIO: Attacker intercepts a valid packet and modifies one bit.")

        # 1. Alice sends a valid message
        original_msg = "Meet at dawn"
        print(f"\n[Step 1] Alice sends valid message: '{original_msg}'")
        package = self.alice.send_secure_message(original_msg)

        # 2. Attacker Intercepts and Modifies Ciphertext
        hex_str = package["encrypted_message"]
        print(
            f"[Step 2] Attacker intercepts encrypted payload:\n  {hex_str}"
        )

        # Flip the last character of the hex string (modifying the last byte)
        modified_hex = hex_str[:-1] + ("0" if hex_str[-1] != "0" else "1")
        package["encrypted_message"] = modified_hex

        print(
            f"[Step 3] Attacker flips the last bit of ciphertext:\n  {modified_hex}"
        )
        print(
            "  NOTE: Signature is NOT updated (Attacker cannot forge Alice's signature)."
        )

        # 3. Bob attempts to process the message
        print(
            "[Step 4] Bob receives tampered package and attempts verification/decryption..."
        )

        # Explanation of failure modes:
        # - If PQC is checked first on the raw ciphertext bytes, it fails immediately (Signature mismatch).
        # - If AES-GCM is checked, it fails because the Tag doesn't match the Ciphertext.
        with self.assertRaises(ValueError) as context:
            self.bob.receive_secure_message(package)

        print(f"\nSUCCESS: System rejected tampered payload.")
        print(f'  Error Message Caught: "{context.exception}"')

    # TEST 3: Quantum Eavesdropping Detection
    def test_qkd_eavesdropping(self):
        # Scenario: Simulate a high error rate (Intercept-Resend Attack)
        # and verify the protocol detects it.
        print("\nTEST: QKD Eavesdropping Detection")
        print(
            "SCENARIO: Comparing a clean quantum channel vs. one with an eavesdropper ('Eve')."
        )

        bb84 = BB84Protocol(key_length=128)

        # Simulate 100 bits
        print("\n[Step 1] Simulating transmission of 100 qubits...")
        alice_bits = [1] * 50 + [0] * 50

        # Bob has bits that match Alice's (Normal case)
        bob_bits_clean = [1] * 50 + [0] * 50

        # Bob has bits with 25% error rate (Eavesdropping case)
        # We flip 25 of the bits
        bob_bits_noisy = bob_bits_clean.copy()
        for i in range(25):
            bob_bits_noisy[i] = 1 - bob_bits_noisy[i]  # Flip bit

        # Check Clean Error Rate
        print("[Step 2] Calculating Error Rate for Clean Channel...")
        error_clean = bb84._check_errors(alice_bits, bob_bits_clean)
        print(f"  -> Clean Channel QBER: {error_clean:.1%}")
        self.assertEqual(error_clean, 0.0, "Clean channel should have 0% error")

        # Check Noisy Error Rate
        print(
            "[Step 3] Calculating Error Rate for Eavesropped Channel (Eve detected)..."
        )
        error_noisy = bb84._check_errors(alice_bits, bob_bits_noisy)
        print(f"  -> Noisy Channel QBER: {error_noisy:.1%}")

        # Assert that high error rate is detected (> 15%)
        print("[Step 4] Verifying Security Threshold (Max allowed: 15%)...")
        if error_noisy > 0.15:
            print(
                "  SUCCESS: High error rate detected! Protocol would abort key generation."
            )
        else:
            print("  FAILURE: Eavesdropper went undetected.")

        self.assertTrue(error_noisy > 0.15, "System failed to detect high error rate!")


if __name__ == "__main__":
    unittest.main()
