#!/usr/bin/env python3
import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import ssl
import threading

class ChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat Client - Login")
        self.ssl_socket = None
        self.username = None  # Will be set after login

        # Login UI setup
        tk.Label(master, text="Server IP:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
        tk.Label(master, text="Port:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
        tk.Label(master, text="Username:").grid(row=2, column=0, padx=5, pady=5, sticky='e')
        tk.Label(master, text="Password:").grid(row=3, column=0, padx=5, pady=5, sticky='e')

        self.server_ip_entry = tk.Entry(master)
        self.server_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        self.server_ip_entry.insert(0, "127.0.0.1")

        self.port_entry = tk.Entry(master)
        self.port_entry.grid(row=1, column=1, padx=5, pady=5)
        self.port_entry.insert(0, "55555")

        self.username_entry = tk.Entry(master)
        self.username_entry.grid(row=2, column=1, padx=5, pady=5)

        self.password_entry = tk.Entry(master, show="*")
        self.password_entry.grid(row=3, column=1, padx=5, pady=5)

        self.login_button = tk.Button(master, text="Login", command=self.login)
        self.login_button.grid(row=4, column=0, columnspan=2, pady=10)

    def login(self):
        server_ip = self.server_ip_entry.get()
        try:
            port = int(self.port_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid port number.")
            return

        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password.")
            return

        # Create an SSL context (for self-signed certificates, disable hostname checking)
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.ssl_socket = context.wrap_socket(client_socket)
            self.ssl_socket.connect((server_ip, port))
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect to server:\n{e}")
            return

        try:
            # Send login credentials in the expected protocol: "LOGIN username password"
            login_message = f"LOGIN {username} {password}"
            self.ssl_socket.send(login_message.encode('utf-8'))
            # Wait for server's response
            response = self.ssl_socket.recv(1024).decode('utf-8')
            if response.startswith("LOGIN SUCCESS"):
                # Remember the username for later comparisons
                self.username = username
                messagebox.showinfo("Success", "Logged in successfully!")
                self.open_chat_window()
            else:
                messagebox.showerror("Login Failed", response)
                self.ssl_socket.close()
        except Exception as e:
            messagebox.showerror("Authentication Error", f"Error during authentication:\n{e}")
            self.ssl_socket.close()

    def open_chat_window(self):
        # Clear login UI
        for widget in self.master.winfo_children():
            widget.destroy()
        self.master.title(f"Secure Chat Client - {self.username}")

        # Chat display area (read-only)
        self.chat_display = scrolledtext.ScrolledText(self.master, state='disabled', width=50, height=20)
        self.chat_display.grid(row=0, column=0, columnspan=2, padx=5, pady=5)

        # Input field for new messages
        self.message_entry = tk.Entry(self.master, width=40)
        self.message_entry.grid(row=1, column=0, padx=5, pady=5)
        self.message_entry.bind("<Return>", lambda event: self.send_message())

        # Send button
        self.send_button = tk.Button(self.master, text="Send", command=self.send_message)
        self.send_button.grid(row=1, column=1, padx=5, pady=5)

        # Set window closing handler for cleanup
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

        # Flag to manage the receiving thread
        self.running = True
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def receive_messages(self):
        """Continuously listen for messages from the server and update the chat display."""
        while self.running:
            try:
                message = self.ssl_socket.recv(1024)
                if not message:
                    self.show_message("Server disconnected.")
                    break
                # The server sends messages prefixed with "username: "
                received_text = message.decode('utf-8')
                self.show_message(received_text)
            except Exception as e:
                self.show_message(f"Error receiving message: {e}")
                break
        try:
            self.ssl_socket.close()
        except Exception:
            pass

    def show_message(self, message):
        # Schedule GUI update in the main thread (Tkinter)
        self.master.after(0, self._update_chat_display, message)

    def _update_chat_display(self, message):
        """Insert a new message into the chat display area."""
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.config(state='disabled')
        self.chat_display.yview(tk.END)

    def send_message(self):
        """Send a message to the server and immediately display it in the chat display with a special marker."""
        message = self.message_entry.get().strip()
        if message:
            # Display the message in the chat area immediately with the (me) marker.
            display_message = f"{self.username} (me): {message}"
            self._update_chat_display(display_message)
            try:
                self.ssl_socket.send(message.encode('utf-8'))
                self.message_entry.delete(0, tk.END)
            except Exception as e:
                messagebox.showerror("Error", f"Error sending message:\n{e}")

    def on_close(self):
        """Cleanly shut down the connection and close the window."""
        self.running = False
        try:
            if self.ssl_socket:
                self.ssl_socket.close()
        except Exception:
            pass
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()
