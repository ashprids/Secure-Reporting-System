from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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


def start_server():
    pass


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