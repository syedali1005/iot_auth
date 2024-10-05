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
import pandas as pd
from sklearn.ensemble import IsolationForest  # Import IsolationForest for anomaly detection
from anomaly_detection import train_model, monitor  # Import anomaly detection functions

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

    # Return only the public key
    return jsonify({
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
        auth_attempts_collection.update_one(
            {'device_id': device_id},
            {'$set': {
                'timestamp': timestamp,
                'device_id': device_id,
                'status': 'failed',
                'success': False,  # Set success to False
                'message': 'Device not registered!'
            }},
            upsert=True
        )
        return jsonify({"message": "Device not registered!"}), 404 
    
    if device_id in active_challenges:
        return jsonify({"message": "Challenge already issued for this device!"}), 400
    
    active_challenges[device_id] = challenge

    auth_attempts_collection.update_one(
        {'device_id': device_id},
        {'$set': {
            'timestamp': timestamp,
            'device_id': device_id,
            'status': 'success',
            'success': True,  # Set success to True
            'message': 'Challenge generated.',
            'challenge': base64.b64encode(challenge).decode()
        }},
        upsert=True
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

    # Assume success for now; adjust based on actual signature validation
    success_status = True  # Implement actual signature validation logic here
    
    # Update the document for the device_id with the response
    auth_attempts_collection.update_one(
        {'device_id': device_id},
        {'$set': {
            'timestamp': timestamp,
            'device_id': device_id,
            'status': 'success',
            'message': 'Success',
            'signature': signature,
            'success': success_status
        }}
    )

    # Train model with new data
    train_model(auth_attempts_collection)

    # Check for anomalies
    if monitor({'device_id': device_id, 'success': success_status}):
        return jsonify({"message": "Anomaly detected!"}), 200
    
    return jsonify({"message": "Success"}), 200

# Route to detect anomalies
@app.route('/detect-anomalies', methods=['GET'])
def detect_anomalies():
    # Fetch all data from MongoDB
    data = list(auth_attempts_collection.find({}, {'_id': 0}))  # Exclude _id from results
    df = pd.DataFrame(data)

    # If no data was fetched, return a message
    if len(df) == 0:
        return jsonify({"message": "No data in the database."}), 400

    # Convert/encode non-numeric fields
    df['success'] = df['success'].astype(int)
    df['device_id'] = pd.factorize(df['device_id'])[0]
    df['status'] = pd.factorize(df['status'])[0]
    df['message'] = pd.factorize(df['message'])[0]
    df['challenge'] = pd.factorize(df['challenge'])[0]

    # Check if there's enough data to train the model
    if len(df) < 3:
        return jsonify({"message": "Not enough data to detect anomalies."}), 400

    # Prepare data for model training
    X = df[['device_id', 'success', 'status', 'message', 'challenge']]

    # Initialize and train the Isolation Forest model
    global model
    model = IsolationForest(contamination=0.1)
    model.fit(X)

    # Monitor for anomalies
    return jsonify({"message": "Model trained successfully!"}), 200

# Route to get authentication attempts log
@app.route('/auth-attempts', methods=['GET'])
def get_auth_attempts():
    attempts = list(auth_attempts_collection.find({}, {'_id': 0}))  # Exclude _id from results
    return jsonify(attempts), 200

if __name__ == '__main__':
    app.run(debug=True) 
