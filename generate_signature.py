# generate_signature.py
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import base64

def generate_signature(private_key, message):
    """Generate a signature for the given message using the provided private key."""
    signature = private_key.sign(
        message,  # No need to encode, already in bytes
        ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(signature).decode('utf-8')
