import rsa
from pymongo import MongoClient
import os
import logging

# Set up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Load the public key from file
with open("public_key.pem", "rb") as f:
    public_key_pem = f.read()
public_key = rsa.PublicKey.load_pkcs1(public_key_pem)

# Load the private key from file
with open("private_key.pem", "rb") as f:
    private_key_pem = f.read()
private_key = rsa.PrivateKey.load_pkcs1(private_key_pem)

def store_credentials():
    print("User Registration")
    email = input("Enter the email address: ")
    app_pass = input("Enter the app-generated password: ")
    alert_server_email = input("Enter the Alert Server email: ")
    alert_server_app_pass = input("Enter the Alert Server app pass: ")
    
    # Connect to MongoDB
    client = MongoClient('mongodb+srv://parayilavinashp:pravaphishing123@prava.0r6tlt7.mongodb.net/?retryWrites=true&w=majority&appName=prava')
    db = client['server-rsa']
    collection = db['credentials']
    
    # Check if the email is already registered
    if collection.find_one({'email': email}):
        logger.warning(f"Email {email} already registered.")
        return
    
    # Encrypt the passwords using the RSA public key
    encrypted_app_pass = rsa.encrypt(app_pass.encode('utf-8'), public_key)
    encrypted_alert_server_app_pass = rsa.encrypt(alert_server_app_pass.encode('utf-8'), public_key)
    
    credentials = {
        'email': email,
        'app_pass': encrypted_app_pass.hex(),  # Convert bytes to hex string
        'alert_server_email': alert_server_email,
        'alert_server_app_pass': encrypted_alert_server_app_pass.hex(),  # Convert bytes to hex string
        'public_key': public_key_pem.decode('utf-8')  # store the public key
    }
    
    result = collection.insert_one(credentials)
    logger.info(f'Registered user with id {email}')
    print("Login to your registered account")

def fetch_credentials():
    # Connect to MongoDB
    client = MongoClient('mongodb+srv://parayilavinashp:pravaphishing123@prava.0r6tlt7.mongodb.net/?retryWrites=true&w=majority&appName=prava')
    db = client['server-rsa']
    collection = db['credentials']

    # Fetch all credentials
    credentials = collection.find()

    # Create a list to store the credentials
    credential_list = []

    # Iterate over the credentials
    for credential in credentials:
        # Extract the email, app pass, alert server email, and alert server app pass
        email = credential['email']
        encrypted_app_pass = credential['app_pass']
        alert_server_email = credential['alert_server_email']
        encrypted_alert_server_app_pass = credential['alert_server_app_pass']

        # Decrypt the app pass and alert server app pass using the private key
        app_pass = rsa.decrypt(bytes.fromhex(encrypted_app_pass), private_key).decode('utf-8')
        alert_server_app_pass = rsa.decrypt(bytes.fromhex(encrypted_alert_server_app_pass), private_key).decode('utf-8')

        # Add the credential to the list
        credential_list.append((email, app_pass, alert_server_email, alert_server_app_pass))

    return credential_list

def remove_user():
    email = input("Enter the email of the user to remove: ")
    
    # Connect to MongoDB
    client = MongoClient('mongodb+srv://parayilavinashp:pravaphishing123@prava.0r6tlt7.mongodb.net/?retryWrites=true&w=majority&appName=prava')
    db = client['server-rsa']
    collection = db['credentials']
    
    # Delete the user
    result = collection.delete_one({'email': email})
    if result.deleted_count > 0:
        logger.info(f"Successfully removed user: {email}")
    else:
        logger.warning(f"User {email} not found.")

def update_user():
    email = input("Enter the email of the user to update: ")
    
    print("Leave fields blank if you don't want to update them.")
    new_app_pass = input("Enter new app pass (optional): ")
    new_alert_server_email = input("Enter new alert server email (optional): ")
    new_alert_server_app_pass = input("Enter new alert server app pass (optional): ")

    # Connect to MongoDB
    client = MongoClient('mongodb+srv://parayilavinashp:pravaphishing123@prava.0r6tlt7.mongodb.net/?retryWrites=true&w=majority&appName=prava')
    db = client['server-rsa']
    collection = db['credentials']

    update_data = {}
    if new_app_pass:
        encrypted_new_app_pass = rsa.encrypt(new_app_pass.encode('utf-8'), public_key).hex()
        update_data['app_pass'] = encrypted_new_app_pass
    if new_alert_server_email:
        update_data['alert_server_email'] = new_alert_server_email
    if new_alert_server_app_pass:
        encrypted_new_alert_server_app_pass = rsa.encrypt(new_alert_server_app_pass.encode('utf-8'), public_key).hex()
        update_data['alert_server_app_pass'] = encrypted_new_alert_server_app_pass
    
    if update_data:
        result = collection.update_one({'email': email}, {'$set': update_data})
        if result.matched_count > 0:
            logger.info(f"Successfully updated user: {email}")
        else:
            logger.warning(f"User {email} not found.")
    else:
        logger.warning("No update data provided.")