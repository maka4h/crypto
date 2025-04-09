import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Constants for algorithm types
RSA_ALGORITHM = "RSA"
ECC_ALGORITHM = "ECC"

def derive_key_pair(cert_pem, salt, iterations, key_size=2048, algorithm=RSA_ALGORITHM, curve_name="secp256r1"):
    """
    Derive a deterministic key pair from a certificate PEM.

    Args:
        cert_pem (str): PEM-encoded certificate
        salt (bytes): Salt for PBKDF2 derivation
        iterations (int): Number of iterations for PBKDF2
        key_size (int): Size of RSA key in bits (only used for RSA)
        algorithm (str): Either RSA_ALGORITHM or ECC_ALGORITHM
        curve_name (str): Name of elliptic curve (only used for ECC)

    Returns:
        tuple: (private_key_pem, public_key_pem)
    """
    # Generate a deterministic seed from the certificate using PBKDF2
    seed = hashlib.pbkdf2_hmac(
        'sha256',
        cert_pem.encode('utf-8'),
        salt,
        iterations
    )

    if algorithm == RSA_ALGORITHM:
        private_key = _derive_rsa_key(seed, key_size)
    elif algorithm == ECC_ALGORITHM:
        private_key = _derive_ecc_key(seed, curve_name)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    # Serialize keys to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_key_pem, public_key_pem

def _derive_rsa_key(seed, key_size):
    """Create a deterministic RSA key from seed material."""
    class DeterministicRandom:
        def __init__(self, seed):
            self.seed = seed
            self.counter = 0

        def __call__(self, n):
            self.counter += 1
            return hashlib.sha512(self.seed + str(self.counter).encode()).digest()[:n]

    rng = DeterministicRandom(seed)

    while True:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,  # Use the exact key size
            backend=default_backend(),
            random_func=rng
        )

        # Ensure the modulus bit length matches the key size
        if private_key.private_numbers().public_numbers.n.bit_length() >= key_size:
            return private_key

def _derive_ecc_key(seed, curve_name):
    """Create a deterministic ECC key from seed material."""
    curve_map = {
        "secp256r1": ec.SECP256R1(),
        "secp384r1": ec.SECP384R1(),
        "secp521r1": ec.SECP521R1(),
    }

    if curve_name not in curve_map:
        raise ValueError(f"Unsupported curve: {curve_name")

    curve = curve_map[curve_name]

    # Generate a deterministic private value
    private_value = int.from_bytes(hashlib.sha512(seed).digest(), byteorder='big') % curve.key_size

    return ec.derive_private_key(private_value, curve, default_backend())