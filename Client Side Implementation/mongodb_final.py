from pymongo import MongoClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import logging

# Set up logging
# Create a logger instance
logger = logging.getLogger(__name__)

# Set the logging level (optional)
logger.setLevel(logging.INFO)

# Generate a key for AES encryption
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

# Encrypt the password using AES
def encrypt_password(password, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(password.encode('utf-8')) + encryptor.finalize()
    return urlsafe_b64encode(iv + ct).decode('utf-8')

# Decrypt the password using AES
def decrypt_password(encrypted_password, key):
    encrypted_password = urlsafe_b64decode(encrypted_password)
    iv = encrypted_password[:16]
    ct = encrypted_password[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_password = decryptor.update(ct) + decryptor.finalize()
    return decrypted_password.decode('utf-8')

# Store credentials in MongoDB
def store_credentials():
    print("User Registration")
    email = input("Enter the email address: ")
    password = input("Enter the password: ")
    app_pass = input("Enter the app-generated password: ")
    alert_server_email = input("Enter the Alert Server email: ")
    alert_server_app_pass = input("Enter the Alert Server app pass: ")
    
    # Connect to MongoDB
    client = MongoClient('mongodb+srv://parayilavinashp:pravaphishing123@prava.0r6tlt7.mongodb.net/?retryWrites=true&w=majority&appName=prava')  # replace with your MongoDB connection string
    db = client['phishing-creds']  # replace with your database name
    collection = db['credentials']  # replace with your collection name
    
    # Check if the email is already registered
    if collection.find_one({'email': email}):
        logger.warning(f"Email {email} already registered.")
        return
    
    salt = os.urandom(16)
    key = generate_key(password.encode('utf-8'), salt)
    encrypted_password = encrypt_password(password, key)
    encrypted_app_pass = encrypt_password(app_pass, key)
    encrypted_alert_server_app_pass = encrypt_password(alert_server_app_pass, key)
    
    credentials = {
        'email': email,
        'password': encrypted_password,
        'app_pass': encrypted_app_pass,
        'alert_server_email': alert_server_email,
        'alert_server_app_pass': encrypted_alert_server_app_pass,
        'salt': urlsafe_b64encode(salt).decode('utf-8')  # store the salt
    }
    
    result = collection.insert_one(credentials)
    logger.info(f'Registered user with id {email}')
    print("Login to your registred account")

def verify_password():
    print("User login")
    email = input("Enter the email: ")
    login_password = input("Enter the password: ")
    
    # Connect to MongoDB
    client = MongoClient('mongodb+srv://parayilavinashp:pravaphishing123@prava.0r6tlt7.mongodb.net/?retryWrites=true&w=majority&appName=prava')  # replace with your MongoDB connection string
    db = client['phishing-creds']  # replace with your database name
    collection = db['credentials']  # replace with your collection name
    
    user_doc = collection.find_one({'email': email})
    
    if user_doc is None:
        logger.warning("User not found.")
        return False
    
    salt = urlsafe_b64decode(user_doc['salt'])
    key = generate_key(login_password.encode('utf-8'), salt)
    
    try:
        decrypted_password = decrypt_password(user_doc['password'], key)
        if decrypted_password == login_password:
            logger.info("Password is correct. Successfully logged In.")
            return {
                'email': user_doc['email'],
                'app_pass': decrypt_password(user_doc['app_pass'], key),
                'alert_server_email': user_doc['alert_server_email'],
                'alert_server_app_pass': decrypt_password(user_doc['alert_server_app_pass'], key)
            }
        else:
            logger.warning("Password is incorrect.")
            return False
    except (UnicodeDecodeError, ValueError) as e:
        # Catch specific decryption errors
        logger.error(f"Error during decryption: {e}")
        logger.warning("Password is incorrect or decryption failed.")
        return False
    except Exception as e:
        # Handle other potential errors
        logger.error(f"Unexpected error: {e}")
        logger.warning("An unexpected error occurred.")
        return False

def delete_user():
    
    email = input("Enter the email: ")
    login_password = input("Enter the password: ")
    
    # Connect to MongoDB
    client = MongoClient('mongodb+srv://parayilavinashp:pravaphishing123@prava.0r6tlt7.mongodb.net/?retryWrites=true&w=majority&appName=prava')  # replace with your MongoDB connection string
    db = client['phishing-creds']  # replace with your database name
    collection = db['credentials']  # replace with your collection name
    
    user_doc = collection.find_one({'email': email})
    
    if user_doc is None:
        logger.warning("User not found.")
        return
    
    salt = urlsafe_b64decode(user_doc['salt'])
    key = generate_key(login_password.encode('utf-8'), salt)
    
    try:
        decrypted_password = decrypt_password(user_doc['password'], key)
        if decrypted_password == login_password:
            collection.delete_one({'email': email})
            logger.info("User deleted successfully.")
        else:
            logger.warning("Password is incorrect.")
    except (UnicodeDecodeError, ValueError) as e:
        # Catch specific decryption errors
        logger.error(f"Error during decryption: {e}")
        logger.warning("Password is incorrect or decryption failed.")
    except Exception as e:
        # Handle other potential errors
        logger.error(f"Unexpected error: {e}")
        logger.warning("An unexpected error occurred.")

