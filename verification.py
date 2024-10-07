import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# Configure logging
logging.basicConfig(level=logging.INFO)

def verify_signature(public_key_pem, signature_bytes, challenge_bytes):
    """Verify the signature using the provided public key and challenge."""
    try:
        # Load the public key
        public_key = serialization.load_pem_public_key(public_key_pem)
        
        # Verify the signature
        public_key.verify(
            signature_bytes,  # Signature as bytes
            challenge_bytes,  # Challenge as bytes
            ec.ECDSA(hashes.SHA256())  # Ensure the same signing algorithm is used
        )
        logging.info("Signature verified successfully.")
        return True  # Signature is valid
    except InvalidSignature:
        logging.error("Signature verification failed: Invalid signature")
        return False  # Invalid signature
    except TypeError as e:
        logging.error(f"Type error: {e}. Ensure signature and challenge are bytes.")
        return False  # Handle type errors
    except Exception as e:
        logging.error(f"Error during signature verification: {e}")
        return False  # Handle any other exceptions
