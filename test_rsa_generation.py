#!/usr/bin/env python3
import base64
import hashlib
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from derive_keys import derive_key_pair_from_pem, RSA_ALGORITHM

def fetch_online_rsa_key(cert_pem, salt, iterations, rsa_key_size):
    """Fetch RSA key from an online service for comparison."""
    url = "https://example-keygen-service.com/api/generate_rsa_key"  # Replace with actual service URL
    payload = {
        "cert_pem": cert_pem,
        "salt": salt.hex(),
        "iterations": iterations,
        "key_size": rsa_key_size
    }
    response = requests.post(url, json=payload)
    response.raise_for_status()
    return response.json()

def test_rsa_key_generation():
    """Test RSA key generation to check determinism and key size"""
    # Fixed test inputs
    test_cert_pem = """-----BEGIN CERTIFICATE-----
MIICVjCCAb8CAg37MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
ODIyMDUyNzIzWhcNMTcwODIxMDUyNzIzWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
ZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMYBBrx5PlP0WNI/ZdzD
+6Pktmurn+F2kQYbtc7XQh8/LTBvCo+P6iZoLEmUA9e7EXLRxgU1CVqeAi7QcAn9
MwBlc8ksFJHB0rtf9pmf8Oza9E0Bynlq/4/Kb1x+d+AyhL7oK9tQwB24uHOueHi1
C/iVv8CSWKiYe6hzN1txYe8rAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAASPdjigJ
kXCqKWpnZ/Oc75EUcMi6HztaW8abUMlYXPIgkV2F7YanHOB7K4f7OOLjiz8DTPFf
jC9UeuErhaA/zzWi8ewMTFZW/WshOrm3fNvcMrMLKtH534JKvcdMg6qIdjTFINIr
evnAhf0cwULaebn+lMs8Pdl7y37+sfluVok=
-----END CERTIFICATE-----"""
    salt = b'0123456789abcdef'
    iterations = 1000
    rsa_key_size = 2048
    
    print("Testing RSA key generation with identical inputs...\n")
    
    # Generate keys multiple times with the same input
    key_results = []
    for i in range(5):
        print(f"Generating key #{i+1}...")
        private_key_pem, public_key_pem, private_key_hex, public_key_hex = derive_key_pair_from_pem(
            test_cert_pem, 
            salt, 
            iterations, 
            rsa_key_size, 
            RSA_ALGORITHM
        )
        
        # Load the private key to check its properties
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None
        )
        
        # Check key size
        key_size = private_key.key_size
        print(f"  - Key size: {key_size} bits")
        
        # Get detailed information about primes
        private_numbers = private_key.private_numbers()
        p = private_numbers.p
        q = private_numbers.q
        n = private_numbers.public_numbers.n
        
        print(f"  - p bit length: {p.bit_length()}")
        print(f"  - q bit length: {q.bit_length()}")
        print(f"  - n (modulus) bit length: {n.bit_length()}")
        
        # Store results for comparison
        key_results.append({
            'private_key_pem': private_key_pem,
            'key_size': key_size,
            'p_bits': p.bit_length(),
            'q_bits': q.bit_length(),
            'n_bits': n.bit_length()
        })
        print()
    
    # Check determinism (all keys should be identical)
    print("Checking determinism:")
    all_identical = all(result['private_key_pem'] == key_results[0]['private_key_pem'] for result in key_results)
    print(f"  - All keys identical: {all_identical}")
    
    # Check key size correctness
    print("\nChecking key sizes:")
    all_correct_size = all(result['key_size'] == rsa_key_size for result in key_results)
    print(f"  - All keys have correct size ({rsa_key_size} bits): {all_correct_size}")
    
    if not all_correct_size:
        print("\nDETAILED KEY SIZE ANALYSIS:")
        for i, result in enumerate(key_results):
            print(f"Key #{i+1}:")
            print(f"  - Reported key size: {result['key_size']} bits")
            print(f"  - p bit length: {result['p_bits']}")
            print(f"  - q bit length: {result['q_bits']}")
            print(f"  - n (modulus) bit length: {result['n_bits']}")
            
            # Calculate p*q manually to verify
            p = private_numbers.p
            q = private_numbers.q
            n_calculated = p * q
            print(f"  - Manually calculated n bit length: {n_calculated.bit_length()}")
            if n_calculated.bit_length() != rsa_key_size:
                print(f"  - ISSUE: Expected {rsa_key_size} bits, but got {n_calculated.bit_length()} bits")
                # Check the highest bit
                highest_bit = (n_calculated >> (rsa_key_size - 1)) & 1
                print(f"  - Highest bit (bit {rsa_key_size-1}) set? {'Yes' if highest_bit else 'No'}")

    # Fetch online RSA key for comparison
    print("\nFetching online RSA key for comparison...")
    online_rsa_key = fetch_online_rsa_key(test_cert_pem, salt, iterations, rsa_key_size)

    # Compare local and online keys
    print("\nComparing local and online RSA keys:")
    print(f"Local Private Key: {key_results[0]['private_key_pem'][:50]}...")
    print(f"Online Private Key: {online_rsa_key['private_key'][:50]}...")
    keys_match = key_results[0]['private_key_pem'] == online_rsa_key['private_key']
    print(f"  - Keys match: {keys_match}")

if __name__ == "__main__":
    test_rsa_key_generation()