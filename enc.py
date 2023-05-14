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
        if file_path.endswith(".enc"):
            # Decrypt data
            decrypted_data = fernet.decrypt(data)
            # Get the original file name by removing the ".enc" extension
            original_file_path = file_path[:-4]
            # Write decrypted data to file
            with open(original_file_path, "wb") as f:
                f.write(decrypted_data)
            # Remove the encrypted file
            os.remove(file_path)
            print(f"Decrypted {file_path}")
        else:
            # Encrypt data
            encrypted_data = fernet.encrypt(data)
            # Add the ".enc" extension to the file name
            encrypted_file_path = file_path + ".enc"
            # Write encrypted data to file
            with open(encrypted_file_path, "wb") as f:
                f.write(encrypted_data)
            # Remove the original file
            os.remove(file_path)
            print(f"Encrypted {file_path}")


print("Finished.")
input()