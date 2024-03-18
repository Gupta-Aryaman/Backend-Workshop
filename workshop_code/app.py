from flask import Flask, request, jsonify
from firebase_admin import credentials, firestore
import firebase_admin
import bcrypt

# Initialize Flask app
app = Flask(__name__)

# Initialize Firebase app
cred = credentials.Certificate("./key.json")
firebase_admin.initialize_app(cred)

db = firestore.client()

# Firebase database reference
ref = db.collection('users')

salt = bcrypt.gensalt()

# Signup endpoint
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data['email']
    password = data['password']

    # Check if user already exists
    if ref.where("email", "==", email).get():
        return jsonify({'message': 'User already exists'}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    print(bcrypt.gensalt())

    # Save user data to Firebase
    user_data = {
        'email': email,
        'password': hashed_password.decode('utf-8')
    }
    ref.document().set(user_data)

    return jsonify({'message': 'Signup successful'}), 201

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']

    # Retrieve user data from Firebase
    users = ref.where("email", "==", email).get()

    if not users:
        return jsonify({'message': 'User not found'}), 404
    
    user_data = users[0].to_dict()

    if bcrypt.checkpw(password.encode('utf-8'), user_data["password"].encode('utf-8')):
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

# Data fetching endpoint
@app.route('/data', methods=['GET'])
def fetch_data():
    # Fetch data from Firebase database
    data = ref.get()

    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True)
