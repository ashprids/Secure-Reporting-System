def generate_rsa_keys():
    pass

def start_server():
    pass

if __name__ == "__main__":
    print("\nSecure Reporting System (SRS) Server")
    print("Choose an option:\n1. Generate RSA keys\n2. Start server\n3. Exit\n")
    option = input("Option: ")
    if option == "1":
        generate_rsa_keys()
    elif option == "2":
        start_server()
    elif option == "3":
        exit()