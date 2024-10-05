from dotenv import load_dotenv  # Import load_dotenv
import os  # Import os for environment variable access
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
import base64
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
from pymongo import MongoClient  # Import MongoClient for MongoDB connection

# Load environment variables from .env file
load_dotenv()
mongo_password = os.getenv('MONGO_DB_PASSWORD')  # Get the MongoDB password from the environment

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Connect to MongoDB using the loaded password
mongo_uri = f"mongodb+srv://admin:{mongo_password}@py-storing.mokmh.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(mongo_uri)
db = client['py-storing']  # Use your actual database name
auth_attempts_collection = db['auth_attempts']  # Use your actual collection name

device_keys = {}
active_challenges = {}  # Track active challenges for each device

# Route to generate and send ECC public-private keys to devices 
@app.route('/generate-keys', methods=['GET'])
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Return keys 
    return jsonify({
        'private_key': pem_private.decode('utf-8'),
        'public_key': pem_public.decode('utf-8')
    })

@app.route('/register', methods=['POST'])
def register_device():
    data = request.json
    device_id = data.get('device_id')
    public_key = data.get('public_key')

    device_keys[device_id] = public_key
    return jsonify({"message": "Device registered successfully!"}), 200

@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.json
    device_id = data['device_id']
    challenge = os.urandom(16)
    device_public_key = device_keys.get(device_id)
    
    timestamp = datetime.utcnow().isoformat()
    
    if device_public_key is None:
        # Update the record for failed attempt or insert a new one
        auth_attempts_collection.update_one(
            {'device_id': device_id},  # Filter by device_id
            {'$set': {
                'timestamp': timestamp,
                'device_id': device_id,
                'status': 'failed',
                'message': 'Device not registered!'
            }},
            upsert=True  # Insert if not exists
        )
        return jsonify({"message": "Device not registered!"}), 404 

    if device_id in active_challenges:
        return jsonify({"message": "Challenge already issued for this device!"}), 400
    
    active_challenges[device_id] = challenge

    # Update the record or insert a new one with the generated challenge
    auth_attempts_collection.update_one(
        {'device_id': device_id},
        {'$set': {
            'timestamp': timestamp,
            'device_id': device_id,
            'status': 'success',
            'message': 'Challenge generated.',
            'challenge': base64.b64encode(challenge).decode()
        }},
        upsert=True  # Insert if not exists
    )
    
    return jsonify({"challenge": base64.b64encode(challenge).decode()}), 200


@app.route('/response', methods=['POST'])
def response():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400 

    device_id = data.get('device_id')
    challenge = data.get('challenge')
    signature = data.get('signature')

    if device_id is None or challenge is None or signature is None:
        return jsonify({"error": "Invalid input data"}), 400 

    timestamp = datetime.utcnow().isoformat()

    if device_id not in active_challenges:
        return jsonify({"error": "No active challenge for this device."}), 400

    # Remove the challenge once it's processed
    del active_challenges[device_id]

    # Update the same document for the device_id with the successful response
    auth_attempts_collection.update_one(
        {'device_id': device_id},
        {'$set': {
            'timestamp': timestamp,
            'device_id': device_id,
            'status': 'success',  # You can change this based on signature validation
            'message': 'Success',
            'signature': signature  # Store the signature if needed
        }}
    )
    
    return jsonify({"message": "Success"}), 200

# Route to get authentication attempts log
@app.route('/auth-attempts', methods=['GET'])
def get_auth_attempts():
    attempts = list(auth_attempts_collection.find({}, {'_id': 0}))  # Exclude _id from results
    return jsonify(attempts), 200

if __name__ == '__main__':
    app.run(debug=True)
