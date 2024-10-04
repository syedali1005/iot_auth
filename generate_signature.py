from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64

# Step 1: Generate a new ECC private key
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

# Step 2: Serialize the private key to PEM format
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Print the private key for reference
print("Generated Private Key:")
print(private_key_pem.decode())

# Step 3: The challenge you received (base64 encoded)
challenge = base64.b64decode("+h4xEd89so26a83Hyk/wUA==")

# Step 4: Sign the challenge
signature = private_key.sign(
    challenge,
    ec.ECDSA(hashes.SHA256())
)

# Step 5: Encode the signature in base64
signature_base64 = base64.b64encode(signature).decode()

print("Signature:", signature_base64)
