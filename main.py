import socket
import threading
import rsa

public_key, private_key = rsa.newkeys(1024)
public_partner = None

choice = input("Queres dar Host(1) ou conectar(2): ")

if choice == "1":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("192.168.1.93", 9999))
    server.listen()

    client, _ = server.accept()
    client.send(public_key.save_pkcs1("PEM"))
    public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
elif choice == "2":
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("192.168.1.93", 9999))
    public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
    client.send(public_key.save_pkcs1("PEM"))
else:
    exit()

def sending_messages(c):
    while True:
        message = input("")
        c.send(rsa.encrypt(message.encode(), public_partner))
        c.send(message.encode())
        print("You: " + message)

def receiving_message(c):
    while True:
        #print("Partner: " + rsa.decrypt(c.recv(1024), private_key).decode())
        print("Partner: " + c.recv(1024).decode())

# Inicie as threads
send_thread = threading.Thread(target=sending_messages, args=(client,))
receive_thread = threading.Thread(target=receiving_message, args=(client,))
send_thread.start()
receive_thread.start()
