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
        # Check if file has ".enc" extension
        if file_path.endswith(".enc"):
            # Open encrypted file
            with open(file_path, "rb") as f:
                data = f.read()
            # Decrypt data
            decrypted_data = fernet.decrypt(data)
            # Remove ".enc" extension from file name
            new_file_path = file_path[:-4]
            # Write decrypted data to file
            with open(new_file_path, "wb") as f:
                f.write(decrypted_data)
            print(f"Decrypted {file_path} -> {new_file_path}")
        else:
            # Open file
            with open(file_path, "rb") as f:
                data = f.read()
            # Encrypt data
            encrypted_data = fernet.encrypt(data)
            # Add ".enc" extension to file name
            new_file_path = file_path + ".enc"
            # Write encrypted data to file
            with open(new_file_path, "wb") as f:
                f.write(encrypted_data)
            print(f"Encrypted {file_path} -> {new_file_path}")

print("Finished.")
input()