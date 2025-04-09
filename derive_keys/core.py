import hashlib
import base64
import os
import struct
import random
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# Key algorithm constants
RSA_ALGORITHM = "rsa"
ECC_ALGORITHM = "ecc"

def derive_key_pair_from_pem(cert_pem: str, salt: bytes, iterations: int = 100000, 
                             key_size: int = 2048, algorithm: str = RSA_ALGORITHM, 
                             curve_name: str = "secp256r1") -> tuple:
    """
    Derives a key pair (private key and public key) from a Certificate PEM.
    The certificate PEM and salt are used to create a seed for the key generation.

    Args:
        cert_pem (str): The certificate in PEM format.
        salt (bytes): A unique salt for the key derivation.
        iterations (int): The number of iterations to use for seed generation (default: 100,000).
        key_size (int): Size of RSA key in bits (default: 2048). Common values: 512, 1024, 2048, 4096.
            Only used when algorithm is 'rsa'.
        algorithm (str): The algorithm to use, either 'rsa' or 'ecc' (default: 'rsa').
        curve_name (str): The name of the ECC curve to use (default: 'secp256r1').
            Only used when algorithm is 'ecc'.
            Common values: 'secp256r1' (NIST P-256), 'secp384r1', 'secp521r1'

    Returns:
        tuple: A tuple containing (private_key_pem, public_key_pem, private_key_hex, public_key_hex).
    """
    # Extract the certificate bytes from the PEM
    cert_bytes = base64.b64decode("".join(cert_pem.splitlines()[1:-1]))
    
    # Use PBKDF2 to generate a seed from the certificate and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    seed_bytes = kdf.derive(cert_bytes)
    
    # For RSA, we need to generate a deterministic key from the seed
    if algorithm.lower() == RSA_ALGORITHM:
        # Use the seed to create a deterministic RSA key
        private_key_obj = create_deterministic_rsa_key(seed_bytes, key_size)
    elif algorithm.lower() == ECC_ALGORITHM:
        # Use the seed to create a deterministic ECC key
        private_key_obj = create_deterministic_ecc_key(seed_bytes, curve_name)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Must be either 'rsa' or 'ecc'.")
    
    # Get the public key from the private key
    public_key_obj = private_key_obj.public_key()
    
    # Extract private key in PEM format
    private_key_pem = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    # Extract public key in PEM format
    public_key_pem = public_key_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Extract private key in DER format and convert to hex
    private_key_der = private_key_obj.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_hex = private_key_der.hex()
    
    # Extract public key in DER format and convert to hex
    public_key_der = public_key_obj.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_hex = public_key_der.hex()
    
    return private_key_pem, public_key_pem, private_key_hex, public_key_hex


def create_deterministic_rsa_key(seed_bytes, key_size):
    """
    Create a deterministic RSA key from a seed.
    
    Args:
        seed_bytes (bytes): The seed to use for key generation.
        key_size (int): Size of RSA key in bits.
        
    Returns:
        RSAPrivateKey: A deterministic RSA private key.
    """
    # Create a SHA-512 hash of the seed
    hasher = hashlib.sha512()
    hasher.update(seed_bytes)
    expanded_seed = hasher.digest()
    
    # For RSA, we'll need to generate deterministic prime numbers based on our seed
    # This is a simplified approach - in a production environment, a more 
    # cryptographically sound method would be used
    p, q = generate_deterministic_primes(expanded_seed, key_size // 2)
    
    # Calculate n = p * q
    n = p * q
    
    # Calculate Euler's totient function: φ(n) = (p-1) * (q-1)
    phi = (p - 1) * (q - 1)
    
    # Choose e = 65537 (standard value for RSA)
    e = 65537
    
    # Calculate d, the modular inverse of e (mod φ(n))
    d = pow(e, -1, phi)
    
    # Create RSA key numbers object
    priv_numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=d % (p-1),
        dmq1=d % (q-1),
        iqmp=pow(q, -1, p),
        public_numbers=rsa.RSAPublicNumbers(
            e=e,
            n=n
        )
    )
    
    # Convert to RSA private key object
    private_key = priv_numbers.private_key(default_backend())
    return private_key


def generate_deterministic_primes(seed, bits):
    """
    Generate two deterministic prime numbers based on a seed.
    
    This is a simplified approach for educational purposes.
    In a real-world scenario, a more cryptographically secure method
    would be used to generate deterministic primes.
    
    Args:
        seed (bytes): Seed bytes for deterministic generation.
        bits (int): Number of bits for each prime.
        
    Returns:
        tuple: Two prime numbers (p, q)
    """
    # Initialize a deterministic random source with our seed
    seed_int = int.from_bytes(seed, byteorder='big')
    random_state = random.Random(seed_int)
    
    # Generate first prime candidate
    p_seed = seed_int & ((1 << 256) - 1)  # Use lower 256 bits for p
    p = find_prime(p_seed, bits, random_state)
    
    # Generate second prime candidate, ensuring it's different from p
    q_seed = (seed_int >> 256) & ((1 << 256) - 1)  # Use upper 256 bits for q
    q = find_prime(q_seed, bits, random_state)
    
    # Ensure p and q are not equal (highly unlikely but check anyway)
    while p == q:
        q_seed = (q_seed * 31) & ((1 << 256) - 1)  # Simple hash to get a new seed
        q = find_prime(q_seed, bits, random_state)
    
    return p, q


def find_prime(seed, bits, random_state):
    """
    Find a prime number of specified bits from a seed.
    
    Args:
        seed (int): Seed for prime generation.
        bits (int): Number of bits for the prime.
        random_state: Random state object for deterministic generation.
        
    Returns:
        int: A prime number
    """
    # Start with seed value
    candidate = seed
    
    # Ensure the number has the highest bit set (for exact bit length)
    candidate |= (1 << (bits - 1))
    
    # Ensure the lowest bit is set (making it odd)
    candidate |= 1
    
    # Find next prime from this starting point
    while not is_probable_prime(candidate, random_state):
        candidate += 2  # Check next odd number
    
    return candidate


def is_probable_prime(n, random_state, k=40):
    """
    Check if a number is probably prime using the Miller-Rabin test.
    
    Args:
        n (int): Number to test for primality.
        random_state: Random state object for deterministic testing.
        k (int): Number of rounds of testing.
        
    Returns:
        bool: True if the number is probably prime, False otherwise.
    """
    # Simple divisibility test by small primes
    for i in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % i == 0:
            return n == i
    
    # Miller-Rabin test
    # Write n as 2^r·d + 1 where d is odd
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random_state.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def create_deterministic_ecc_key(seed_bytes, curve_name):
    """
    Create a deterministic ECC key from a seed.
    
    Args:
        seed_bytes (bytes): The seed to use for key generation.
        curve_name (str): The name of the ECC curve to use.
        
    Returns:
        EllipticCurvePrivateKey: A deterministic ECC private key.
    """
    # Map curve name to cryptography curve object
    curve_map = {
        'secp256r1': ec.SECP256R1(),
        'secp384r1': ec.SECP384R1(),
        'secp521r1': ec.SECP521R1(),
        'secp224r1': ec.SECP224R1(),
        'secp192r1': ec.SECP192R1(),
    }
    
    curve = curve_map.get(curve_name, ec.SECP256R1())  # Default to SECP256R1 if not found
    
    # Get the curve's order (n) - these are the standard orders for NIST curves
    curve_orders = {
        'secp256r1': 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,  # NIST P-256 curve order
        'secp384r1': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,  # NIST P-384 curve order
        'secp521r1': 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,  # NIST P-521 curve order
        'secp224r1': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D,  # NIST P-224 curve order
        'secp192r1': 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831,  # NIST P-192 curve order
    }
    
    curve_order = curve_orders.get(curve_name)
    if curve_order is None:
        # Default to secp256r1 if curve not found in orders
        curve_order = curve_orders['secp256r1']
    
    # Hash the seed to get deterministic bytes
    hasher = hashlib.sha512()
    hasher.update(seed_bytes)
    hashed_seed = hasher.digest()
    
    # Convert to an integer
    seed_int = int.from_bytes(hashed_seed, byteorder='big')
    
    # Ensure the private value is in the valid range for the curve (1 <= private_value < curve_order)
    private_value = 1 + (seed_int % (curve_order - 1))
    
    # Create a private key from this value
    private_key = ec.derive_private_key(
        private_value, 
        curve,
        default_backend()
    )
    
    return private_key


def get_available_curves():
    """
    Returns a list of available ECC curves.
    
    Returns:
        list: A list of curve names that can be used with the derive_key_pair_from_pem function.
    """
    return ['secp256r1', 'secp384r1', 'secp521r1', 'secp224r1', 'secp192r1']