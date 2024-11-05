from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA
from datetime import datetime
import os, socket, tomllib, base64



# Load configuration file
with open("config.toml", "rb") as f:
    config = tomllib.load(f)



def generate_rsa_keys():
    key_pair = RSA.generate(2048)
    public_key = key_pair.publickey().exportKey()
    private_key = key_pair.exportKey()

    with open("server_public-key.pem", "wb") as f:
        f.write(public_key)
    with open("server_private-key.pem", "wb") as f:
        f.write(private_key)
    print("\nRSA keys have been generated.\nPublic key saved as server_public-key.pem\nPrivate key saved as server_private-key.pem")



# Decrypt AES-256
def decrypt(ciphertext: bytes, key: bytes, iv: bytes, filename: str,) -> bytes:
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
            print("\nIncoming connection from "+addr[0]+" rejected (IP not whitelisted).")
            conn.close()
            return
        
        # Receive data and save in data variable
        print("\nIncoming connection from:",addr[0])
        data = conn.recv(1024)
        full_data = data
        while data:
            data = conn.recv(1024)
            full_data += data
        print("Data received.")

        # Open report.toml and assign variables
        with open("report.toml", "wb") as f:
            f.write(full_data)
        with open("report.toml", "rb") as f:
            report = tomllib.load(f)

        iv = base64.b64decode(report["iv"])
        aes_key = base64.b64decode(report["key"])
        current_date = datetime.now().strftime("%Y-%m-%d") # Generate the current date string
        save_path = f"Reports/{addr[0]}/{current_date}" # Saves in Reports/IP/Date

        if not os.path.exists(save_path):
            os.makedirs(save_path)

        for key, value in report.items():
            if key in ["iv", "key", "data"]: # Skip any non-file data
                continue
            file_path = os.path.join(save_path, f"{key}.txt")
            decrypted_data = decrypt(base64.b64decode(value['txt']), aes_key, iv, key)
            with open(file_path, 'w') as f:
                f.write(decrypted_data.decode().replace("\\n", "\n"))
            
        print("\nLog files from", addr[0], "saved at Reports/"+save_path+":")
        print("\n".join(os.listdir(save_path)))
        #os.remove("report.toml")



if __name__ == "__main__":
    print("\nSecure Reporting System (SRS) Server")
    print("Choose an option:\n1. Generate RSA keys\n2. Start server\n3. Exit\n")
    option = input("Option: ")
    if option == "1":
        choice = input("Are you sure? This will overwrite the existing keys. (y/N): ")
        if choice.lower() == "y":
            generate_rsa_keys()
        else:
            print("Operation cancelled.")
    elif option == "2":
        start_server()
    elif option == "3":
        exit()