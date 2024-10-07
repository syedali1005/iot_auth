from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

# Load private key
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

# Create a challenge
challenge = "nxPuUjMsQAuWnReygwYs5Q=="

# Generate a signature
signature = private_key.sign(challenge.encode(), ec.ECDSA(hashes.SHA256()))
encoded_signature = base64.b64encode(signature).decode('utf-8')

print("Encoded Signature:", encoded_signature)

# Load public key
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Verify the signature
public_key.verify(signature, challenge.encode(), ec.ECDSA(hashes.SHA256()))
print("Signature verified successfully!")
