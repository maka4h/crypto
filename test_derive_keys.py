import unittest
import base64
import os
from derive_keys import derive_key_pair_from_pem


class TestDeriveKeys(unittest.TestCase):
    def setUp(self):
        # Create a sample certificate PEM for testing
        self.test_cert_pem = """-----BEGIN CERTIFICATE-----
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
        self.salt = os.urandom(16)  # Generate a random salt for testing
        self.iterations = 1000  # Lower iterations for faster tests

    def test_derive_key_pair_from_pem_returns_tuple(self):
        """Test that the function returns a tuple"""
        result = derive_key_pair_from_pem(self.test_cert_pem, self.salt, self.iterations)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_derive_key_pair_from_pem_returns_bytes(self):
        """Test that the returned keys are bytes"""
        private_key, public_key = derive_key_pair_from_pem(self.test_cert_pem, self.salt, self.iterations)
        self.assertIsInstance(private_key, bytes)
        self.assertIsInstance(public_key, bytes)

    def test_derive_key_pair_from_pem_key_length(self):
        """Test that the keys have the expected length (32 bytes)"""
        private_key, public_key = derive_key_pair_from_pem(self.test_cert_pem, self.salt, self.iterations)
        self.assertEqual(len(private_key), 32)
        self.assertEqual(len(public_key), 32)

    def test_derive_key_pair_from_pem_deterministic(self):
        """Test that the function is deterministic with the same inputs"""
        result1 = derive_key_pair_from_pem(self.test_cert_pem, self.salt, self.iterations)
        result2 = derive_key_pair_from_pem(self.test_cert_pem, self.salt, self.iterations)
        self.assertEqual(result1, result2)

    def test_derive_key_pair_from_pem_different_salt(self):
        """Test that different salts produce different keys"""
        salt1 = os.urandom(16)
        salt2 = os.urandom(16)
        result1 = derive_key_pair_from_pem(self.test_cert_pem, salt1, self.iterations)
        result2 = derive_key_pair_from_pem(self.test_cert_pem, salt2, self.iterations)
        self.assertNotEqual(result1, result2)

    def test_derive_key_pair_from_pem_different_iterations(self):
        """Test that different iteration counts produce different keys"""
        result1 = derive_key_pair_from_pem(self.test_cert_pem, self.salt, 1000)
        result2 = derive_key_pair_from_pem(self.test_cert_pem, self.salt, 2000)
        self.assertNotEqual(result1, result2)

    def test_private_different_from_public_key(self):
        """Test that the private and public keys are different"""
        private_key, public_key = derive_key_pair_from_pem(self.test_cert_pem, self.salt, self.iterations)
        self.assertNotEqual(private_key, public_key)

    def test_derive_key_pair_default_iterations(self):
        """Test function with default iterations parameter"""
        # With default iterations
        result = derive_key_pair_from_pem(self.test_cert_pem, self.salt)
        private_key, public_key = result
        self.assertIsInstance(private_key, bytes)
        self.assertIsInstance(public_key, bytes)
        self.assertEqual(len(private_key), 32)
        self.assertEqual(len(public_key), 32)


if __name__ == '__main__':
    unittest.main()