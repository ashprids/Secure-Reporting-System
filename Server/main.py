from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from typing import Tuple
import os, socket, tomllib
from datetime import datetime



# Load configuration file
with open("config.toml", "rb") as f:
    config = tomllib.load(f)



def generate_rsa_keys():
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        # Save the keys to files
        # We have to specify the encoding and format of the keys because the keys are in the format of bytes, not strings.
        with open("server_private-key.pem", "wb") as f:  # Private key
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,  # PEM (Privacy Enhanced Mail) is a standard for storing cryptographic keys.
                format=serialization.PrivateFormat.PKCS8,  # PKCS8 is a standard syntax for storing private key information.
                encryption_algorithm=serialization.NoEncryption()  # Stores the private key in plaintext, since the server storing it has restricted access anyway.
            ))
        with open("server_public-key.pem", "wb") as f:  # Public key
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo  # SubjectPublicKeyInfo is a standard syntax for storing public key information.
            ))
        
        print("\nRSA keys generated successfully:\nserver_private-key.pem\nserver_public-key.pem")
    except Exception as e:
        print("\nAn error occurred while generating RSA keys:", e)



# Generate AES key from a password (for demonstration)
def generate_key(password: str, salt: bytes) -> bytes:
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
	length=32,  # AES-256 key length
	salt=salt,
	iterations=100000,
	backend=default_backend()
	)
	return kdf.derive(password.encode())



# Decrypt AES-256
def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	decryptor = cipher.decryptor()
	decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
	# Remove padding
	unpadder = padding.PKCS7(128).unpadder()
	plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()
	return plaintext



def start_server():
    allowed_ips = config["client"]["whitelist"]

    # Create a socket and listen for incoming connections
    server_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", config["server"]["port"]))
    server_socket.listen(1)
    print("\nServer started.\nListening on port", config["server"]["port"])

    conn, addr = server_socket.accept()
    with conn:

        # Check if the client IP is allowed
        if addr[0] not in allowed_ips:
            print("\nConnection from unauthorized IP ("+addr[0]+") rejected.")
            conn.close()
            return
        
        # Receive data and save in data variable
        print("\nReceiving connection from:",addr[0])
        data = conn.recv(1024)
        full_data = data
        while data:
            data = conn.recv(1024)
            full_data += data

        # Decrypt report file with AES-256
        iv = full_data[:16]
        key = full_data[16:48]
        decrypted_data = decrypt(full_data[48:], key, iv)

        # Create directory for reports if it doesn't exist
        current_date = datetime.now().strftime("%Y-%m-%d") # Generate the current date string
        save_path = f"Reports/{addr[0]}/{current_date}" # Saves in Reports/IP/Date

        if not os.path.exists(save_path):
            os.makedirs(save_path)
        
        with open(f"report.toml", 'wb') as f:
            f.write(decrypted_data)
            
        with open(f"report.toml", 'rb') as f:
            decrypted_report = tomllib.load(f)

        # Save the contents of the report file to individual files
        decrypted_report = tomllib.loads(decrypted_data.decode('utf-8'))
        for key, value in decrypted_report.items():
            file_path = os.path.join(save_path, f"{key}.txt")
            with open(file_path, 'w') as f:
                f.write('\n'.join(value.values()).replace("\\n", "\n"))

        print("Log files from", addr[0], "saved at Reports/"+addr[0]+"/"+current_date+".")
        os.remove("report.toml")



if __name__ == "__main__":
    print("\nSecure Reporting System (SRS) Server")
    print("Choose an option:\n1. Generate RSA keys\n2. Start server\n3. Exit\n")
    option = input("Option: ")
    if option == "1":
        choice = input("Are you sure? This will overwrite the existing keys. (y/n): ")
        if choice.lower() == "y":
            generate_rsa_keys()
        else:
            print("Operation cancelled.")
    elif option == "2":
        start_server()
    elif option == "3":
        exit()