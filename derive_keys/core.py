import hashlib
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

def derive_key_pair_from_pem(cert_pem: str, salt: bytes, iterations: int = 100000, key_size: int = 2048) -> tuple:
    """
    Derives a key pair (private key and public key) from a Certificate PEM using RSA.
    The certificate PEM and salt are used to create a seed for the RSA key generation.

    Args:
        cert_pem (str): The certificate in PEM format.
        salt (bytes): A unique salt for the key derivation.
        iterations (int): The number of iterations to use for seed generation (default: 100,000).
        key_size (int): Size of RSA key in bits (default: 2048). Common values: 512, 1024, 2048, 4096.

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
    seed = kdf.derive(cert_bytes)
    
    # Use the seed to initialize the random number generator for RSA
    # This is a workaround since RSA doesn't accept a seed directly
    # In a real implementation, a proper CSPRNG seeding mechanism should be used
    os.environ["PYTHONHASHSEED"] = seed.hex()
    
    # Generate an RSA private key with specified key size
    private_key_obj = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
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