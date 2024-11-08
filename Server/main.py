from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from datetime import datetime
import os, socket, tomllib, base64, hashlib



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
    print("\nWaiting for incoming connections...\n")

    conn, addr = server_socket.accept()
    with conn:

        # Check if the client IP is allowed
        if addr[0] not in allowed_ips:
            print("["+addr[0]+"] Connection rejected (IP not whitelisted).")
            conn.close()
            return
        
        # Receive data and save in data variable
        print("["+addr[0]+"] Incoming connection")
        data = conn.recv(1024)
        full_data = data
        while data: # Keep receiving data until it's all been received
            data = conn.recv(1024)
            full_data += data
        print("["+addr[0]+"] Data received")

        sha512 = full_data[:64]
        report = full_data[64:].decode('utf-8')

        # Decrypt the report data with the server's RSA private key
        private_key = RSA.import_key(open("server_private-key.pem").read())
        cipher = PKCS1_OAEP.new(private_key)

        # Split the report into 214-character blocks and decrypt each block
        decrypted_report = b''
        for i in range(0, len(report), 344):  # 344 bytes per base64-encoded block
            block = report[i:i+344]
            decoded_block = base64.b64decode(block)  # Decode base64 to get the original 256 bytes
            decrypted_block = cipher.decrypt(decoded_block)
            decrypted_report += decrypted_block

        # Verify SHA-512 checksum
        if sha512 != hashlib.sha512(decrypted_report).digest():
            print("["+addr[0]+"] ERROR: SHA-512 checksum mismatch. Operation aborted.")
            return
        print("["+addr[0]+"] SHA-512 checksum verified.")

        # Open report.toml and assign variables
        with open("report.toml", "wb") as f:
            f.write(decrypted_report)
        with open("report.toml", "rb") as f:
            report = tomllib.load(f)

        iv = base64.b64decode(report["iv"])
        aes_key = base64.b64decode(report["key"])
        current_date = datetime.now().strftime("%Y-%m-%d") # Generate the current date string
        save_path = f"Reports/{addr[0]}/{current_date}" # Saves in Reports/IP/Date

        if not os.path.exists(save_path):
            os.makedirs(save_path)

        # Decrypt and save each file with AES-256
        for key, value in report.items():
            if key in ["iv", "key", "data"]: # Skip any non-file data
                continue
            file_path = os.path.join(save_path, f"{key}.txt")
            decrypted_data = decrypt(base64.b64decode(value['txt']), aes_key, iv, key)
            with open(file_path, 'w') as f:
                f.write(decrypted_data.decode().replace("\\n", "\n"))
            
        print("["+addr[0]+"] Log files saved:")
        for i in os.listdir(save_path):
            print("            > "+i)
        os.remove("report.toml")



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
        print("\nSecure Reporting System (Server) started successfully.")
        print("Server Port:		"+str(config["server"]["port"]))
        while True:
            start_server()
    elif option == "3":
        exit()