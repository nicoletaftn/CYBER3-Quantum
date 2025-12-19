import time
import sys
import os
from Crypto.Random import get_random_bytes  # For generating random payload

# Make sure `src` (the package root) is on sys.path so tests can import project modules
# when running this file directly or when the working directory is the repository root.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
# FIX IMPORTS to point to the src package
from src.qkd.bb84 import BB84Protocol
from src.pqc.ml_dsa_auth import MLDSAAuthenticator
from src.crypto.aes_cipher import AESCipher


# Configuration
N_ITERATIONS = 100
TEST_MESSAGE = b"Test message for signing performance."


def run_qkd_benchmark(key_length):
    # Measures the time taken to generate a BB84 key.
    print(f"\n  [QKD Benchmark] Starting BB84 key generation ({key_length} bits)...")
    print(f"  -> Initializing Quantum Network Simulation...")
    qkd_protocol = BB84Protocol(key_length=key_length)

    start_time = time.time()
    try:
        # Note: This step includes network setup and the full quantum simulation.
        print("  -> Running BB84 Protocol (Transmission -> Measurement -> Sifting)...")
        qkd_protocol.generate_key()
    except Exception as e:
        print(f"    ✗ QKD failed: {e}")
        return float("inf")
    finally:
        # Cleanup the simulated network
        qkd_protocol.cleanup()

    end_time = time.time()
    duration = end_time - start_time
    print(f"  ✓ QKD Complete in {duration:.2f}s")
    return duration


def run_pqc_benchmark():
    # Measures the time for ML-DSA-65 Keypair, Sign, and Verify.
    print(f"  [PQC Benchmark] Testing ML-DSA-65 (Post-Quantum Digital Signatures)")
    authenticator = MLDSAAuthenticator()

    # --- 1. Keypair Generation ---
    print("  -> Measuring Keypair Generation (1 iteration)...")
    start_time_kp = time.time()
    public_key, private_key = authenticator.generate_keypair()
    end_time_kp = time.time()
    keypair_time = end_time_kp - start_time_kp

    signature = authenticator.sign(TEST_MESSAGE)

    # --- 2. Signing Overhead ---
    print(
        f"  -> Measuring Signing Operation (Averaged over {N_ITERATIONS} iterations)..."
    )
    sign_times = []
    for _ in range(N_ITERATIONS):
        start_time_sign = time.time()
        # We time the signing operation
        authenticator.sign(TEST_MESSAGE)
        end_time_sign = time.time()
        sign_times.append(end_time_sign - start_time_sign)

    avg_sign_time = sum(sign_times) / N_ITERATIONS

    # --- 3. Verification Overhead ---
    print(
        f"  -> Measuring Verification Operation (Averaged over {N_ITERATIONS} iterations)..."
    )
    verify_times = []
    for _ in range(N_ITERATIONS):
        start_time_verify = time.time()
        # 'signature' is now guaranteed to be bound to a valid value
        is_valid = authenticator.verify(TEST_MESSAGE, signature, public_key)
        end_time_verify = time.time()
        verify_times.append(end_time_verify - start_time_verify)
        if not is_valid:
            raise Exception("Verification failed during benchmark")

    avg_verify_time = sum(verify_times) / N_ITERATIONS

    return {
        "keypair_time": keypair_time,
        "avg_sign_time": avg_sign_time,
        "avg_verify_time": avg_verify_time,
    }


def run_aes_benchmark():
    # Measures the time for AES-256-GCM encryption and decryption.
    print("\n  [AES Benchmark] Testing AES-256-GCM (Symmetric Encryption)")

    # Use the 256-bit key (32 bytes) derived by the AESCipher class
    key = b"0" * 32
    cipher = AESCipher(key=key)

    # Use a standard payload size (1024 bytes = 1 KB)
    payload_size = 1024
    payload = get_random_bytes(payload_size)
    print(f"  -> Payload Size: {payload_size} bytes (1 KB)")

    encrypt_times = []
    decrypt_times = []

    print(
        f"  -> Measuring Encryption/Decryption (Averaged over {N_ITERATIONS} iterations)..."
    )
    for _ in range(N_ITERATIONS):
        # Encryption
        start_time_enc = time.time()
        encrypted = cipher.encrypt(payload)
        end_time_enc = time.time()
        encrypt_times.append(end_time_enc - start_time_enc)

        # Decryption
        start_time_dec = time.time()
        # This will verify the GCM tag and decrypt
        cipher.decrypt(encrypted)
        end_time_dec = time.time()
        decrypt_times.append(end_time_dec - start_time_dec)

    avg_encrypt_time = sum(encrypt_times) / N_ITERATIONS
    avg_decrypt_time = sum(decrypt_times) / N_ITERATIONS

    return {
        "size": payload_size,
        "avg_encrypt_time": avg_encrypt_time,
        "avg_decrypt_time": avg_decrypt_time,
    }


def main():
    print("=" * 70)
    print("       HYBRID CRYPTOGRAPHY PERFORMANCE BENCHMARKS")
    print("=" * 70)
    print(f"Configuration: {N_ITERATIONS} iterations per operation.")
    print(
        f"Note: QKD times are highly dependent on the QuNetSim library and local machine speed.\n"
    )

    # 1. PQC Overhead
    print("---- 1. PQC (ML-DSA-65) Overhead ----")
    pqc_results = run_pqc_benchmark()
    print(f"  Result:")
    print(f"  > Keypair Generation: {pqc_results['keypair_time'] * 1e6:.3f} microseconds")
    print(
        f"  > Avg. Signature Time:  {pqc_results['avg_sign_time'] * 1e6:.3f} microseconds"
    )
    print(
        f"  > Avg. Verification Time: {pqc_results['avg_verify_time'] * 1e6:.3f} microseconds\n"
    )

    # 2. Symmetric Encryption/Decryption Overhead
    print("---- 2. Symmetric Encryption (AES-256-GCM) Overhead ----")
    aes_results = run_aes_benchmark()
    print(f"  Result:")
    print(f"  > Payload Size: {aes_results['size']} bytes (1 KB)")
    print(
        f"  > Avg. Encryption Time: {aes_results['avg_encrypt_time'] * 1e6:.3f} microseconds"
    )
    print(
        f"  > Avg. Decryption Time: {aes_results['avg_decrypt_time'] * 1e6:.3f} microseconds\n"
    )

    # 3. QKD Key Generation Rate
    print("---- 3. QKD (BB84 Simulation) Key Generation Rate ----")
    print(
        "  Note: This benchmarks the full protocol simulation (Transmission + Sifting)."
    )

    time_128 = run_qkd_benchmark(128)
    print(f"  Result: 128-bit Key Time: {time_128:.2f} seconds")

    # Run the 256-bit test only if the 128-bit test succeeded reasonably
    if time_128 < 300:  # Max 5 minutes for 128-bit, otherwise skip 256-bit
        time_256 = run_qkd_benchmark(256)
        print(f"  Result: 256-bit Key Time: {time_256:.2f} seconds\n")
    else:
        print("  ! Skipping 256-bit test due to excessively long 128-bit test.")
        time_256 = float("inf")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
