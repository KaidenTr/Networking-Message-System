Secure Networking Chat Application

This project demonstrates a full‑featured networking system with:

- TLS/SSL Encryption: All communication between the client and server is secured.
- User Authentication: Clients must log in using a username and password.
- Enhanced Error Handling: Robust error checking for disconnections and network issues.
- GUI Client: The client uses a Tkinter‑based GUI for an improved user experience.

Files

- server.py:
  The secure server that listens for TLS‑encrypted connections, authenticates users, handles incoming messages, and broadcasts them to other clients.

- client_gui.py: 
  The GUI‑based client that connects securely to the server, prompts for login credentials, and allows real‑time chat through a friendly interface.

- server.pem and server.key (required):  
  TLS certificate and key files to secure the connection.  
  _For testing, you can generate these using:_  
  ```bash
  openssl req -new -x509 -days 365 -nodes -out server.pem -keyout server.key

