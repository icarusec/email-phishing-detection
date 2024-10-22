import rsa

# Generate a new RSA key pair
(public_key, private_key) = rsa.newkeys(2048)

# Save the public key to a file
with open("public_key.pem", "wb") as f:
    f.write(public_key.save_pkcs1())

# Save the private key to a file
with open("private_key.pem", "wb") as f:
    f.write(private_key.save_pkcs1())