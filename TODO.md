# Secure Reporting System (SRS)

### TODO
- [ ] Complete TODO list (Ashton)
  - [x] Client/server software
  - [ ] Network & security design
  - [ ] Measuring network performance
  - [ ] Validation and Testing


### Client software
Ensure the program does the following:
- [ ] Create a function for sending log files securely to the server
  - The user should be able to specify the files and IP/Port of the server in a config file
  - The files must be encrypted with an AES-256 key, and the data + key sent to the server via RSA-2048.
    - The server's public key must be used for RSA-2048 encryption, so only the server can decrypt it.
  - A SHA-512 must be generated for verification. Choose the most efficient + secure methods.

- [ ] Send the reports automatically every day at a specified time
  - Time should be specified in the config file
  - Once sent, clear the log files (to prevent reports containing duplicate info)

- [ ] Allow Level 3 systems to manually send reports
  - This functionality should exist in a separate python file from the server file
  - System levels specified in the config file


### Server software
Ensure the program does the following:
- [ ] Generate public and private RSA-2048 keys
  - The public key is configured in client config files
- [ ] Receive the reports
  - Listen on the port specified in config
  - Decrypt data with server private key, use SHA-256 key to decrypt reports and validate with SHA-512.
  - Only accept reports from IPs specified in server config file.
- [ ] Store the reports
  - Reports should be stored in the Server/Reports directory.
  - Each IP should have its own directory where reports are stored.
- The process of receiving and storing reports should run in their own threads so multiple
clients can be processed at once.


### Write README
- [ ] Specify that the network's ACLs (Access Control Lists) should be configured appropriately
  - The filesystem ACL should prevent anyone under Level 3 from modifying any of this program's files
  - The networking ACL should only allow SFTP connections from the IPs of the specified networks


### Live demonstration
- [ ] PowerPoint presentation
- [ ] Demonstration script