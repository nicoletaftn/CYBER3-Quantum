"""
Test script to verify all libraries are installed correctly
"""
import os

# Fix for M3 Mac - set library path for liboqs
liboqs_lib_path = "/opt/homebrew/opt/liboqs/lib"
if os.path.exists(liboqs_lib_path):
    os.environ['DYLD_LIBRARY_PATH'] = f"{liboqs_lib_path}:{os.environ.get('DYLD_LIBRARY_PATH', '')}"

def test_qunetsim():
    try:
        from qunetsim.components import Host, Network
        print("✓ QuNetSim")
        return True
    except Exception as e:
        print(f"✗ QuNetSim: {e}")
        return False

def test_liboqs():
    try:
        import oqs
        signer = oqs.Signature("ML-DSA-65")
        public_key = signer.generate_keypair()
        signature = signer.sign(b"test")
        assert signer.verify(b"test", signature, public_key)
        print("✓ liboqs (ML-DSA-65)")
        return True
    except Exception as e:
        print(f"✗ liboqs: {e}")
        return False

def test_pycryptodome():
    try:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        AES.new(get_random_bytes(32), AES.MODE_EAX)
        print("✓ PyCryptodome (AES-256)")
        return True
    except Exception as e:
        print(f"✗ PyCryptodome: {e}")
        return False

if __name__ == "__main__":
    print("Testing Environment Setup...")
    print("-" * 30)
    
    results = [test_qunetsim(), test_liboqs(), test_pycryptodome()]
    
    print("-" * 30)
    if all(results):
        print("✓ Ready to start development!")
    else:
        print("✗ Setup incomplete")