from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
import base64
import os
from flask import Flask, request, jsonify
from flask_cors import CORS


app = Flask(__name__)
CORS(app)

device_keys = {}

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
    print("Method:", request.method)
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
    
    if device_public_key is None:
        return jsonify({"message": "Device not registered!"}), 404
    
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

    return jsonify({"message": "Success"}), 200

if __name__ == '__main__':
    app.run(debug=True)
