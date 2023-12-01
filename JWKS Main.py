import os
import time
import jwt
import random
import string
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Generate RSA Key Pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return private_pem, public_pem

# Initialize key pair and metadata
key_list = []
jwks = {
    "keys": [
        
                  
        
    ]
}



jwt_kids = set()  # Set to store used kid values for JWTs
jwk_kids = set()  # Set to store used kid values for JWKs

private_keys = set() # Set to store used Private Keys
public_keys = set() # Set to store used Public Keys

private_key, public_key = generate_rsa_key_pair()
private_keys.add(private_key)
public_keys.add(public_key)
key_id = "1"  # You can generate unique key IDs as needed
 # Expiry in 1 minute

# Endpoint for serving public keys in JWKS format
@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    unexpired_keys = {   
    "keys": [
        
                  
        
        ]
    }
    id = request.args.get('key_id')
    if id is not None:
        if get_key_by_kid(jwks, id) is not None:
            return get_key_by_kid(jwks, id)
        else:
            return jsonify({}), 404
    else:
        # Get the current time as a datetime object
        current_time = datetime.now()
        # Add one minute to the current time
        one_minute_later = current_time + timedelta(minutes=1)

        key_expiry = int(one_minute_later.timestamp())

        key_id = get_random_kid()
        while key_id in jwk_kids:
            key_id = get_random_kid()
        jwk_kids.add(key_id)
        private_key, public_key = generate_rsa_key_pair()
        private_keys.add(private_key)
        public_keys.add(public_key)
        new_key = {
            "kid": key_id,
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": public_key.split('\n')[1],  # Modulus
            "e": public_key.split('\n')[2],   # Exponent
            "exp": key_expiry
        }
        jwks["keys"].append(new_key)
        for key in jwks["keys"]:
            current_time = int(time.time())
            expiry = key["exp"]
            if current_time < expiry:
                unexpired_keys["keys"].append(key)
        
        return jsonify(unexpired_keys)

# Search through the stored JWKS for the JWK with the specified kid
def get_key_by_kid(jwks, target_kid):
    for key in jwks["keys"]:
        if key.get("kid") == target_kid:
            return key
    return None 

def get_random_kid():
    characters = string.ascii_letters + string.digits
    random_kid = ''.join(random.choice(characters) for _ in range(5))
    return random_kid


# Endpoint for generating and signing JWTs
@app.route('/auth', methods=['POST'])
def authenticate():
    expired = request.args.get('expired')

    if expired:
        # Get the current time as a datetime object
        current_time = datetime.now()
        # Add one minute to the current time
        one_minute_later = current_time + timedelta(minutes=1)

        key_expiry = int(one_minute_later.timestamp())

        expiry_timestamp = key_expiry - 3600  # Make it one hour ago to simulate an expired key
    else:
        # Get the current time as a datetime object
        current_time = datetime.now()
        # Add one minute to the current time
        one_minute_later = current_time + timedelta(minutes=1)

        key_expiry = int(one_minute_later.timestamp())

        expiry_timestamp = key_expiry
        
    # Check if the request contains JSON data
    if request.is_json:
        json_data = request.get_json()  # Parse the JSON data
        payload = {
            "sub": json_data,  # Subject
            "exp": expiry_timestamp
        }
    else:
        payload = {
        "sub": "auth",  # Subject
        "exp": expiry_timestamp
        }

    key_id = get_random_kid()
    while key_id in jwt_kids or key_id in jwk_kids:
        key_id = get_random_kid()
    jwt_kids.add(key_id)
    token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': key_id})
    return jsonify({"token": token})

if __name__ == '__main__':
    app.run(port=8080)