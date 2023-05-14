import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def get_key(password):

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password)
    return base64.urlsafe_b64encode(digest.finalize())

# Ask for password
password = input("Enter password: ").encode('utf-8')
# Generate Fernet key using password
key = get_key(password)
# Generate Fernet object using key
fernet = Fernet(key)
# Encrypt or decrypt files in "enc" folder
for root, dirs, files in os.walk("enc"):
    for file in files:
        # Get file path
        file_path = os.path.join(root, file)
        # Open file
        with open(file_path, "rb") as f:
            data = f.read()
        # Encrypt or decrypt data
        try:
            # Decrypt data
            decrypted_data = fernet.decrypt(data)
            # Write decrypted data to file
            with open(file_path, "wb") as f:
                f.write(decrypted_data)
            print(f"Decrypted {file_path}")
        except:
            # Encrypt data
            encrypted_data = fernet.encrypt(data)
            # Write encrypted data to file
            with open(file_path, "wb") as f:
                f.write(encrypted_data)
            print(f"Encrypted {file_path}")