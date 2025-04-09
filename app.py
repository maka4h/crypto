import base64
import datetime
import os
import secrets
from typing import Optional
import uvicorn
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from derive_keys import derive_key_pair_from_pem

app = FastAPI(title="Key Derivation Service")

# Create templates directory if it doesn't exist
os.makedirs("templates", exist_ok=True)

# Setup Jinja2 templates
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def get_form(request: Request):
    """Render the HTML form for key derivation"""
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/derive-keys", response_class=HTMLResponse)
async def derive_keys(
    request: Request,
    cert_pem: str = Form(...),
    salt: Optional[str] = Form(None),
    iterations: int = Form(100000),
    key_size: int = Form(2048),
    generate_cert: bool = Form(False),
    generate_salt: bool = Form(False)
):
    """
    Derive keys from the provided certificate PEM and salt.
    
    If generate_cert is True, a self-signed certificate will be generated.
    If generate_salt is True, a random salt will be generated.
    """
    # Generate a self-signed certificate if requested
    if generate_cert:
        cert_pem = generate_self_signed_cert()
    
    # Generate a random salt if requested or if no salt provided
    if generate_salt or not salt:
        salt_bytes = secrets.token_bytes(16)
        salt = base64.b64encode(salt_bytes).decode('utf-8')
    else:
        # Convert base64 string to bytes
        try:
            salt_bytes = base64.b64decode(salt)
        except Exception:
            salt_bytes = salt.encode('utf-8')  # Fallback to UTF-8 encoding
    
    # Derive key pair - now returning both PEM and hex formats
    private_key_pem, public_key_pem, private_key_hex, public_key_hex = derive_key_pair_from_pem(
        cert_pem, 
        salt_bytes, 
        iterations, 
        key_size
    )
    
    # Salt in raw and base64 formats for display
    salt_raw = salt_bytes.hex()  # Using hex representation for raw bytes
    salt_b64 = base64.b64encode(salt_bytes).decode('utf-8')
    
    # Get a human-readable representation of the salt
    salt_decoded = ""
    for b in salt_bytes:
        if 32 <= b <= 126:  # Printable ASCII range
            salt_decoded += chr(b)
        else:
            salt_decoded += f"\\x{b:02x}"  # Show as hex for non-printable characters
    
    # Return results
    return templates.TemplateResponse(
        "result.html", 
        {
            "request": request,
            "private_key_pem": private_key_pem,
            "public_key_pem": public_key_pem,
            "private_key_hex": private_key_hex,
            "public_key_hex": public_key_hex,
            "cert_pem": cert_pem,
            "salt": salt_b64,
            "salt_raw": salt_raw,
            "salt_decoded": salt_decoded,
            "iterations": iterations,
            "key_size": key_size
        }
    )

@app.get("/generate-cert")
async def generate_cert_endpoint():
    """Generate a new self-signed certificate and return it as JSON."""
    cert_pem = generate_self_signed_cert()
    return JSONResponse(content={"cert_pem": cert_pem})

@app.get("/generate-salt")
async def generate_salt_endpoint():
    """Generate a random salt and return it as JSON."""
    salt_bytes = secrets.token_bytes(16)
    salt = base64.b64encode(salt_bytes).decode('utf-8')
    return JSONResponse(content={"salt": salt})

def generate_self_signed_cert():
    """Generate a self-signed certificate and return its PEM representation."""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Corp"),
        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        # Valid starting now
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).sign(private_key, hashes.SHA256())
    
    # Serialize to PEM format
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
    
    return cert_pem

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)