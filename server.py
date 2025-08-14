#!/usr/bin/env python3
import socket
import ssl
import threading

# Predefined user credentials for authentication
users = {
    "user1": "password1",
    "user2": "password2"
}

# Global list and mapping of connected secure client sockets and usernames
clients = []
client_usernames = {}

def broadcast(message, sender_socket):
    """
    Send the message to all connected clients except for the sender.
    """
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message)
            except Exception as e:
                print(f"[BROADCAST ERROR] {e}")
                client.close()
                if client in clients:
                    clients.remove(client)

def handle_client(client_socket, address):
    """
    Handle new connections: Authenticate the client and then process incoming messages.
    """
    print(f"[NEW CONNECTION] {address} connected.")
    
    try:
        # Expecting a login string in the format: "LOGIN username password"
        login_data = client_socket.recv(1024).decode('utf-8')
        if not login_data.startswith("LOGIN "):
            client_socket.send("LOGIN FAILED: Invalid protocol.".encode('utf-8'))
            client_socket.close()
            return

        parts = login_data.split()
        if len(parts) != 3:
            client_socket.send("LOGIN FAILED: Incorrect credentials format.".encode('utf-8'))
            client_socket.close()
            return

        username, password = parts[1], parts[2]
        if username in users and users[username] == password:
            # Authentication successful
            client_usernames[client_socket] = username
            client_socket.send("LOGIN SUCCESS".encode('utf-8'))
            print(f"[AUTH SUCCESS] {username} logged in from {address}")
        else:
            client_socket.send("LOGIN FAILED: Invalid username or password.".encode('utf-8'))
            client_socket.close()
            return

    except Exception as e:
        print(f"[AUTH ERROR] Authentication failed for {address}: {e}")
        client_socket.close()
        return

    # Handle continuous incoming messages after successful login
    while True:
        try:
            message = client_socket.recv(1024)
            if not message:
                print(f"[DISCONNECT] {address} disconnected.")
                break

            # Prefix the message with the sender's username
            username = client_usernames.get(client_socket, "Unknown")
            full_message = f"{username}: {message.decode('utf-8')}"
            print(f"[{address}] {full_message}")
            broadcast(full_message.encode('utf-8'), client_socket)
        except Exception as e:
            print(f"[ERROR] Connection with {address} encountered an error: {e}")
            break

    # Clean up when a client disconnects
    client_socket.close()
    if client_socket in clients:
        clients.remove(client_socket)
    if client_socket in client_usernames:
        print(f"[LOGOUT] {client_usernames[client_socket]} logged out.")
        del client_usernames[client_socket]
    print(f"[CLEANUP] Connection with {address} has been closed.")

def main():
    host = "127.0.0.1"   # Change if listening on a public interface
    port = 55555         # Choose a suitable non-privileged port

    # Create an SSL context for secure communications
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.pem", keyfile="server.key")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[LISTENING] Secure server is listening on {host}:{port}")

    while True:
        client_socket, address = server_socket.accept()
        try:
            # Wrap the client socket in an SSL context
            secure_socket = context.wrap_socket(client_socket, server_side=True)
        except ssl.SSLError as ssl_error:
            print(f"[SSL ERROR] {ssl_error}")
            client_socket.close()
            continue

        clients.append(secure_socket)
        thread = threading.Thread(target=handle_client, args=(secure_socket, address))
        thread.daemon = True
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {len(clients)}")

if __name__ == "__main__":
    main()
