import requests
import json
import base64

SERVER_URL = "http://localhost:8000/test-derive-keys"
NUM_REQUESTS = 5

# Fixed input parameters for testing determinism
TEST_CERT_PEM = """-----BEGIN CERTIFICATE-----
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
SALT_BYTES = b'deterministic_salt_123'
SALT_B64 = base64.b64encode(SALT_BYTES).decode('utf-8')
ITERATIONS = 1000  # Use a lower iteration count for faster testing
RSA_KEY_SIZE = 2048
ECC_CURVE = "secp256r1"

def test_determinism(algorithm, key_size=None, curve_name=None):
    """Sends multiple requests for a given algorithm and checks determinism."""
    print(f"\nTesting determinism for {algorithm.upper()}...")
    payload = {
        "cert_pem": TEST_CERT_PEM,
        "salt": SALT_B64,
        "iterations": ITERATIONS,
        "algorithm": algorithm,
    }
    if algorithm.lower() == "rsa":
        payload["key_size"] = key_size
    elif algorithm.lower() == "ecc":
        payload["curve_name"] = curve_name

    responses = []
    try:
        for i in range(NUM_REQUESTS):
            print(f"  Sending request {i + 1}/{NUM_REQUESTS}...")
            response = requests.post(SERVER_URL, json=payload)
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
            responses.append(response.json())
            print(f"    Response status: {response.status_code}")

        # Check if all responses are identical
        first_response = responses[0]
        all_identical = all(resp == first_response for resp in responses[1:])

        print(f"\nResults for {algorithm.upper()}:")
        if all_identical:
            print("  ✅ SUCCESS: All responses were identical. Server is deterministic for these inputs.")
            # print(f"  Sample Private Key PEM: {first_response.get('private_key_pem', 'N/A')[:60]}...")
        else:
            print("  ❌ FAILURE: Responses were not identical. Server is NOT deterministic for these inputs.")
            # Optionally print differing responses for debugging
            # for i, resp in enumerate(responses):
            #     print(f"    Response {i+1}: {json.dumps(resp)[:100]}...")
        return all_identical

    except requests.exceptions.RequestException as e:
        print(f"  ❌ ERROR: Could not connect to the server or request failed: {e}")
        return False
    except Exception as e:
        print(f"  ❌ ERROR: An unexpected error occurred: {e}")
        return False

if __name__ == "__main__":
    print(f"Starting server determinism test against {SERVER_URL}")
    print(f"Using {NUM_REQUESTS} requests per test case.")

    # Ensure the server is running before starting the test
    try:
        requests.get(SERVER_URL.replace("/test-derive-keys", "/"), timeout=2)
        print("Server connection successful.")
    except requests.exceptions.ConnectionError:
        print("\nError: Could not connect to the server.")
        print(f"Please ensure the server is running using './run_server.sh' before running this script.")
        exit(1)

    # Test RSA
    rsa_deterministic = test_determinism("rsa", key_size=RSA_KEY_SIZE)

    # Test ECC
    ecc_deterministic = test_determinism("ecc", curve_name=ECC_CURVE)

    print("\n--- Test Summary ---")
    print(f"RSA Determinism: {'PASS' if rsa_deterministic else 'FAIL'}")
    print(f"ECC Determinism: {'PASS' if ecc_deterministic else 'FAIL'}")

    if rsa_deterministic and ecc_deterministic:
        print("\nAll tests passed!")
    else:
        print("\nSome tests failed.")
        exit(1)
