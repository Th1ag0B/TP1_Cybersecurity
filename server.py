import socket
import threading
import time
import hashlib
import json

clients = {}
lock = threading.Lock()
public_keys_file = "public_keys.json"  # Nome do arquivo para armazenar as chaves públicas

def load_public_keys():
    try:
        with open(public_keys_file, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_public_keys(public_keys):
    with open(public_keys_file, "w") as file:
        json.dump(public_keys, file)

    send_online_users()

def broadcast(message, sender_name=None):
    for client_name, client_socket in clients.items():
        if client_name != sender_name:
            try:
                client_socket.send(message.encode())
            except ConnectionError:
                print(f"Erro ao enviar mensagem para {client_name}")
                remove_client(client_name)

def handle_client(client_socket, client_name):
    global clients

    try:
        while True:
            option = client_socket.recv(1024).decode()
            if option.startswith('2|'):
                parts = option.split('|')
                if len(parts) >= 3:
                    message = parts[1]
                    message_hash = parts[2]
                    broadcast(f"{client_name}|{message}|{message_hash}", sender_name=client_name)
                else:
                    print("Mensagem recebida com formato inválido:", option)
            elif option.startswith('3|'):
                parts = option.split('|')
                if len(parts) >= 4:
                    recipient = parts[1]
                    private_message = parts[2]
                    encrypted_message = bytes.fromhex(private_message)
                    print(len(encrypted_message))
                    print(private_message)
                    client_message_hash = parts[3]
                    send_private_message(client_name, recipient, private_message, client_message_hash)
                else:
                    print("Mensagem de chat privado recebida com formato inválido:", option)
            elif option.startswith('4|'):
                parts = option.split('|')
                if len(parts) >= 2:
                    recipient = parts[1]
                    send_private_chat_history(client_name, recipient)
                else:
                    print("Solicitação de histórico de chat privado recebida com formato inválido:", option)
    except (ConnectionResetError, ConnectionAbortedError):
        remove_client(client_name)



def send_online_users():
    online_users = "ONLINE_USERS:" + ",".join(clients.keys())
    for client_socket in clients.values():
        try:
            client_socket.send(online_users.encode())
        except ConnectionError:
            pass

def send_private_message(sender, recipient, message, message_hash):
    recipient_socket = clients.get(recipient)
    if recipient_socket:
        try:
            # Envia a mensagem junto com o hash para o destinatário
            recipient_socket.send(f"PRIVATE_MESSAGE:{sender}:{message}:{message_hash}".encode())
        except ConnectionError:
            print(f"Erro ao enviar mensagem privada para {recipient}")

def send_private_chat_history(client_name, recipient):
    client_socket = clients.get(client_name)
    if client_socket:
        try:
            client_socket.send(f"PRIVATE_CHAT_HISTORY:{recipient}".encode())
        except ConnectionError:
            print(f"Erro ao enviar histórico de chat privado para {client_name}")

def remove_client(client_name):
    lock.acquire()
    del clients[client_name]
    lock.release()
    broadcast(f"{client_name} desconectado")
    print(f"Cliente {client_name} desconectado.")

def accept_connections(server_socket):
    threading.Thread(daemon=True).start()

    while True:
        client_socket, client_address = server_socket.accept()
        client_name = client_socket.recv(1024).decode()
        print(f"Cliente {client_name} conectado.")
        
        client_public_key = client_socket.recv(1024)  # Recebe a chave pública do cliente
        print(f"Chave pública do cliente {client_name}:")
        print(client_public_key.decode())

        lock.acquire()
        clients[client_name] = client_socket
        lock.release()

        # Carrega as chaves públicas existentes do arquivo
        public_keys = load_public_keys()

        # Atualiza ou insere a chave pública do cliente no dicionário de chaves públicas
        public_keys[client_name] = client_public_key.decode()

        # Salva o dicionário atualizado de chaves públicas no arquivo
        save_public_keys(public_keys)

        threading.Thread(target=handle_client, args=(client_socket, client_name), daemon=True).start()

def main():
    server_host = 'localhost'
    server_port = 9999
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((server_host, server_port))
        server_socket.listen()
    
        print(f"Servidor esperando conexões em {server_host}:{server_port}")

        accept_connections(server_socket)

if __name__ == "__main__":
    main()
    