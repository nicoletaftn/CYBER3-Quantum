"""
BB84 Quantum Key Distribution Protocol using QuNetSim
Generates shared secret keys between Alice and Bob
"""

from qunetsim.components import Host, Network
from qunetsim.objects import Qubit
import random
import time


class BB84Protocol:
    """Implements BB84 quantum key distribution protocol"""
    
    def __init__(self, key_length=256):
        """
        Initialize BB84 protocol
        
        Args:
            key_length: Target length of the final shared key in bits
        """
        self.key_length = key_length
        self.network = None
        self.alice = None
        self.bob = None
        
    def setup_network(self):
        """Initialize quantum network with Alice and Bob"""
        self.network = Network.get_instance()
        
        self.alice = Host('Alice')
        self.bob = Host('Bob')
        
        self.alice.add_connection('Bob')
        self.bob.add_connection('Alice')
        
        self.alice.start()
        self.bob.start()
        
        self.network.add_hosts([self.alice, self.bob])
        self.network.start()
        
        time.sleep(1)
        print("✓ Quantum network initialized")
        
    def generate_key(self):
        """
        Execute BB84 protocol to generate shared secret key
        
        Returns:
            bytes: Shared secret key
        """
        if not self.alice or not self.bob:
            self.setup_network()
        
        n_qubits = self.key_length * 4
        
        print(f"Generating {self.key_length}-bit key via BB84...")
        print(f"  - Sending {n_qubits} qubits")
        
        alice_bits = [random.randint(0, 1) for _ in range(n_qubits)]
        alice_bases = [random.randint(0, 1) for _ in range(n_qubits)]
        bob_bases = [random.randint(0, 1) for _ in range(n_qubits)]
        bob_bits = []
        
        for i in range(n_qubits):
            qubit = Qubit(self.alice)
            
            if alice_bits[i] == 1:
                qubit.X()
            
            if alice_bases[i] == 1:
                qubit.H()
            
            self.alice.send_qubit('Bob', qubit)
            
            if i % 100 == 0:
                time.sleep(0.1)
        
        time.sleep(1)
        
        for i in range(n_qubits):
            qubit = self.bob.get_qubit('Alice', wait=5)
            
            if qubit is None:
                bob_bits.append(random.randint(0, 1))
                continue
            
            if bob_bases[i] == 1:
                qubit.H()
            
            measurement = qubit.measure()
            bob_bits.append(measurement)
        
        print(f"  - Received {len([b for b in bob_bits if b is not None])}/{n_qubits} qubits")
        
        matching_indices = [i for i in range(len(alice_bases)) 
                          if alice_bases[i] == bob_bases[i]]
        print(f"  - Basis match: {len(matching_indices)}/{n_qubits} qubits")
        
        alice_key_bits = [alice_bits[i] for i in matching_indices]
        bob_key_bits = [bob_bits[i] for i in matching_indices]
        
        error_rate = self._check_errors(alice_key_bits, bob_key_bits)
        print(f"  - Error rate: {error_rate:.1%}")
        
        if error_rate > 0.15:
            print(f"  ! Warning: High error rate, possible eavesdropping")
        
        if len(alice_key_bits) < self.key_length:
            raise Exception(f"Not enough bits after reconciliation: {len(alice_key_bits)} < {self.key_length}")
        
        final_bits = alice_key_bits[:self.key_length]
        key = self._bits_to_bytes(final_bits)
        
        print(f"✓ Generated {len(key)} bytes ({self.key_length} bits)")
        print(f"  Shared Secret Key (Hexidecimal): {key.hex()}") 
        
        return key
    
    def _check_errors(self, alice_bits, bob_bits, sample_size=50):
        """Sample some bits to check for errors/eavesdropping"""
        if len(alice_bits) < sample_size:
            sample_size = max(1, len(alice_bits) // 4)
        
        if sample_size == 0:
            return 0.0
        
        sample_indices = random.sample(range(len(alice_bits)), min(sample_size, len(alice_bits)))
        errors = sum(1 for i in sample_indices if alice_bits[i] != bob_bits[i])
        
        return errors / len(sample_indices)
    
    def _bits_to_bytes(self, bits):
        """Convert list of bits to bytes"""
        while len(bits) % 8 != 0:
            bits.append(0)
        
        byte_array = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            byte_array.append(byte)
        
        return bytes(byte_array)
    
    def cleanup(self):
        """Stop network and cleanup"""
        if self.network:
            self.network.stop(stop_hosts=True)
            print("✓ Network stopped")