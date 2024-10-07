import logging
from dotenv import load_dotenv
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import base64
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
from pymongo import MongoClient
import pandas as pd
from sklearn.ensemble import IsolationForest
from anomaly_detection import train_model, monitor
from verification import verify_signature
from generate_signature import generate_signature

# Load environment variables from .env file
load_dotenv()
mongo_password = os.getenv('MONGO_DB_PASSWORD')

# Configure logging
logging.basicConfig(level=logging.INFO)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Connect to MongoDB
mongo_uri = f"mongodb+srv://admin:{mongo_password}@py-storing.mokmh.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(mongo_uri)
db = client['py-storing']
auth_attempts_collection = db['auth_attempts']

device_keys = {}
private_keys = {}  # Store private keys separately
active_challenges = {}

@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    data = request.json
    device_id = data.get('device_id')

    if not device_id:
        logging.error("Device ID is required.")
        return jsonify({"error": "Device ID is required!"}), 400

    try:
        # Key generation logic
        private_key = ec.generate_private_key(ec.SECP256R1())
        
        # Serialize private and public keys
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        pem_public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Store the private key in the private_keys dictionary
        private_keys[device_id] = pem_private

        logging.info(f"Keys generated for device: {device_id}")

        return {
            'private_key': pem_private.decode('utf-8'),
            'public_key': pem_public.decode('utf-8'),
            'device_id': device_id
        }
    except Exception as e:
        logging.error(f"Error generating keys: {str(e)}")
        return jsonify({"error": "Failed to generate keys."}), 500

@app.route('/register', methods=['POST'])
def register_device():
    data = request.json
    device_id = data.get('device_id')
    public_key = data.get('public_key')

    if not device_id or not public_key:
        logging.error("Device ID or public key missing.")
        return jsonify({"error": "Device ID and public key are required!"}), 400

    # Store the public key as bytes
    device_keys[device_id] = public_key.encode()
    logging.info(f"Device registered: {device_id}")

    # Generate a challenge
    challenge = os.urandom(16)
    active_challenges[device_id] = challenge

    auth_attempts_collection.update_one(
        {'device_id': device_id},
        {'$set': {
            'device_id': device_id,
            'challenge': base64.b64encode(challenge).decode(),
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'registered',
            'success': True
        }},
        upsert=True
    )

    return jsonify({"message": "Device registered successfully!", "challenge": base64.b64encode(challenge).decode()}), 200

@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.json
    device_id = data.get('device_id')

    if not device_id:
        logging.error("Device ID is required.")
        return jsonify({"error": "Device ID is required!"}), 400

    # Retrieve the challenge from the active challenges
    challenge = active_challenges.get(device_id)
    timestamp = datetime.utcnow().isoformat()

    if challenge is None:
        logging.warning(f"No active challenge for device: {device_id}")
        return jsonify({"message": "No active challenge for this device!"}), 400

    # Retrieve the private key for the device
    private_key_pem = private_keys.get(device_id)

    if private_key_pem is None:
        logging.error(f"Private key not found for device: {device_id}")
        return jsonify({"error": "Private key not found for this device!"}), 400

    try:
        # Load the private key
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )

        # Ensure proper padding for base64 decoding (multiple of 4)
        challenge_base64 = base64.b64encode(challenge).decode('utf-8')
        challenge_base64 += '=' * (-len(challenge_base64) % 4)  # Add necessary padding

        # Decode the base64-encoded challenge back to bytes (if it's still in base64)
        challenge_bytes = base64.b64decode(challenge_base64)

        # Use the generate_signature function to sign the challenge
        signature = generate_signature(private_key, challenge_bytes)

        # Store the signature in the database
        auth_attempts_collection.update_one(
            {'device_id': device_id},
            {'$set': {
                'timestamp': timestamp,
                'device_id': device_id,
                'status': 'success',
                'success': True,
                'message': 'Challenge authenticated.',
                'challenge': challenge_base64,  # Store the base64-encoded challenge
                'signature': signature
            }},
            upsert=True
        )

        return jsonify({"message": "Challenge authenticated!", "signature": signature}), 200

    except Exception as e:
        logging.error(f"An error occurred during authentication: {str(e)}")
        return jsonify({"error": f"An error occurred during authentication: {str(e)}"}), 500

@app.route('/response', methods=['POST'])
def response():
    data = request.get_json()
    if not data:
        logging.error("No data provided in response.")
        return jsonify({"error": "No data provided"}), 400 

    device_id = data.get('device_id')
    challenge = data.get('challenge')
    signature = data.get('signature')

    if device_id is None or challenge is None or signature is None:
        logging.error("Invalid input data.")
        return jsonify({"error": "Invalid input data"}), 400 

    timestamp = datetime.utcnow().isoformat()

    # Ensure device has an active challenge
    if device_id not in active_challenges:
        logging.error(f"No active challenge for device: {device_id}")
        return jsonify({"error": "No active challenge for this device."}), 400

    # Retrieve the public key for this device
    public_key_pem = device_keys.get(device_id)
    if public_key_pem is None:
        logging.error(f"No public key found for device: {device_id}")
        return jsonify({"error": "No public key found for this device."}), 400

    # Ensure the public key is in bytes
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode()

    # Decode the base64-encoded challenge
    try:
        challenge_bytes = base64.b64decode(challenge)
    except Exception as e:
        logging.error(f"Error decoding challenge: {e}")
        return jsonify({"error": "Invalid challenge format"}), 400

    # Decode the base64-encoded signature
    try:
        signature_bytes = base64.b64decode(signature)
    except Exception as e:
        logging.error(f"Error decoding signature: {e}")
        return jsonify({"error": "Invalid signature format"}), 400

    # Verify the signature
    success_status = verify_signature(public_key_pem, signature_bytes, challenge_bytes)
    logging.info(f"Verification result for device {device_id}: {success_status}")

    # Check if the received challenge matches the active challenge
    expected_challenge = active_challenges[device_id]
    if challenge_bytes != expected_challenge:
        logging.warning(f"Challenge mismatch for device {device_id}. Marking as anomaly.")
        message = 'Anomaly Detected: Challenge mismatch detected.'
        auth_attempts_collection.update_one(
            {'device_id': device_id},
            {'$set': {
                'timestamp': timestamp,
                'device_id': device_id,
                'status': message,
                'message': message,
                'signature': signature,
                'success': False
            }}
        )
        return jsonify({"message": message}), 200

    # Only store the authentication attempt if the signature is valid
    if success_status:
        message = 'Normal Activity: Success'
        auth_attempts_collection.update_one(
            {'device_id': device_id},
            {'$set': {
                'timestamp': timestamp,
                'device_id': device_id,
                'status': message,
                'message': message,
                'signature': signature,
                'success': success_status
            }}
        )
        logging.info(f"Authentication attempt stored for device {device_id}.")
    else:
        message = 'Anomaly Detected: Invalid signature.'
        logging.warning(f"Failed authentication attempt for device {device_id}. Invalid signature.")

        auth_attempts_collection.update_one(
            {'device_id': device_id},
            {'$set': {
                'timestamp': timestamp,
                'device_id': device_id,
                'status': message,
                'message': message,
                'signature': signature,
                'success': False
            }}
        )

    # Train anomaly detection model
    train_model(auth_attempts_collection)

    return jsonify({"message": message}), 200



@app.route('/train-model', methods=['POST'])
def train_model_endpoint():
    """Endpoint to train the anomaly detection model."""
    result = train_model(auth_attempts_collection)
    if result:
        return jsonify({"message": "Model trained successfully!"}), 200
    else:
        return jsonify({"message": "Not enough data to train the model."}), 400


@app.route('/auth-attempts', methods=['GET'])
def get_auth_attempts():
    # Retrieve all authentication attempts from the database
    attempts = list(auth_attempts_collection.find({}))
    for attempt in attempts:
        attempt['_id'] = str(attempt['_id'])  # Convert ObjectId to string
    return jsonify(attempts), 200

if __name__ == '__main__':
    app.run(debug=True)
