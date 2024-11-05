from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from Crypto.PublicKey import RSA
from typing import Tuple
import os, socket, tomllib, schedule, time, threading, base64



# Load configuration file
with open("config.toml", "rb") as f:
    config = tomllib.load(f)



# Generate AES-256 key from a password
def generate_key(password: str, salt: bytes) -> bytes:
	kdf = PBKDF2HMAC(
	algorithm = hashes.SHA256(),
	length = 32,
	salt = salt,
	iterations = 100000,
	backend = default_backend()
	)
	return kdf.derive(password.encode())



# Encrypt plaintext with AES-256
def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> Tuple[bytes, bytes, bytes]:
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	encryptor = cipher.encryptor()

	# Add plaintext padding (128 bit / 16 byte)
	padder = padding.PKCS7(128).padder()
	padded_data = padder.update(plaintext) + padder.finalize()
	ciphertext = encryptor.update(padded_data) + encryptor.finalize()
	return ciphertext



# Files are stored in a single report.toml file so they can all be sent at once.
# The server will split them into their original files once decrypted.
def send_reports():
	password = config["client"]["password"]  # Key will be derived from this password
	salt = os.urandom(16)  # Random salt for key derivation
	iv = os.urandom(16)  # Initialization vector

	key = generate_key(password, salt)

	with open("report.toml", "w") as f:
		# Because of escape characters in the key and iv, we need to encode them in base64
		f.write(f'iv = """{base64.b64encode(iv).decode("utf-8")}"""\n')
		f.write(f'key = """{base64.b64encode(key).decode("utf-8")}"""\n')

		for file in config["client"]["targets"]:
			with open(file, "rb") as f2:
				file_data = f2.read()
				encrypted_data = encrypt(file_data, key, iv)
				
			f.write(file + ''' = """''' + base64.b64encode(encrypted_data).decode("utf-8") + '''"""\n''')
			print(f"Added {file} to report.")

	# Connect to the server
	client_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client_socket.connect((config["server"]["address"], config["server"]["port"]))
	with open("report.toml", 'rb') as f:
		report_data = f.read()
	client_socket.sendall(report_data)
	print (f"\nReport sent successfully.")
	client_socket.close()
	#os.remove("report.toml")



# Schedule the reports to be sent at a specific time
def schedule_reports():
	schedule.every().day.at(config["client"]["send_time"]).do(send_reports)
	while True:
		schedule.run_pending()
		time.sleep(60)



if __name__ == "__main__":
	threading.Thread(target=schedule_reports).start()
	print("Secure Reporting System (Client) started successfully.\n")
	print("Server IP:		", config["server"]["address"])
	print("Server Port:		", config["server"]["port"])
	
	while True:
		print("\nReports will automatically send at", config["client"]["send_time"], "every day.")
		choice = input("Press ENTER to send a report now. ")
		if choice == "":
			send_reports()
		else:
			exit()