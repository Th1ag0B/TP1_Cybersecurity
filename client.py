import os
import socket
import threading
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
import json
import hashlib

public_keys_file = "public_keys.json"  # Nome do arquivo para armazenar as chaves públicas
recipient_public_key = None

class ChatApplication:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat Application")
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.online_users = []
        self.private_chats = {}  # Dicionário para manter as janelas de chat privado
        self.current_chat = None  # Usuário com quem o chat privado está aberto
        self.own_username = None  # Nome do próprio usuário
        self.public_key = None  # Chave pública do cliente
        
        # Estilo
        self.master.config(bg="#191919")  # Fundo cinza escuro

        # Janela para inserir o nome do usuário
        self.setup_name_input()

        self.online_users_listbox = None  # Inicializamos como None
        self.chat_text = None

    def load_public_keys(self):
        try:
            with open(public_keys_file, "r") as file:
                return json.load(file)
        except FileNotFoundError:
            return {}
    
    def setup_name_input(self):
        # Frame para o nome de usuário
        self.name_frame = tk.Frame(self.master, bg="#191919")  # Fundo cinza escuro
        self.name_frame.pack(expand=True, pady=50)

        self.name_label = tk.Label(self.name_frame, text="Welcome to Secure Chat", bg="#191919", fg="#FFFFFF", font=("Arial", 18))
        self.name_label.pack(pady=20)

        self.name_label = tk.Label(self.name_frame, text="Enter your Username:", bg="#191919", fg="#FFFFFF", font=("Arial", 14))
        self.name_label.pack()

        self.name_entry = tk.Entry(self.name_frame, font=("Arial", 14))
        self.name_entry.pack(pady=10)

        self.name_submit_button = tk.Button(self.name_frame, text="Enter Chat", command=self.submit_name, bg="#FF5A5F", fg="white", font=("Arial", 14, "bold"))
        self.name_submit_button.pack()

    def submit_name(self):
        name = self.name_entry.get()
        if name:
            self.own_username = name  # Armazena o nome do próprio usuário
            self.client_socket.connect(('localhost', 9999))
            self.client_socket.send(name.encode())
            self.generate_and_send_public_key()  # Gerar e enviar a chave pública
            self.name_frame.pack_forget()
            threading.Thread(target=self.receive_messages).start()
            self.setup_chat_ui()
        else:
            messagebox.showerror("Error", "Please enter a valid name.")

    def generate_and_send_public_key(self):
        global private_key
        # Gerar um par de chaves RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Obter a chave pública
        public_key = private_key.public_key()

        # Serializar a chave pública para poder ser enviada
        serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Enviar a chave pública para o servidor
        self.client_socket.sendall(serialized_public_key)
 
    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode()
                if message.startswith("ONLINE_USERS:"):
                    if self.online_users_listbox:  # Verificamos se o UI já foi configurado
                        self.update_online_users(message.split(':')[1])
                elif message.startswith("PRIVATE_MESSAGE:"):
                    parts = message.split(':')
                    sender = parts[1]
                    private_message = parts[2]
                    received_hash = parts[3]

                    decrypted_message = private_key.decrypt(
                        bytes.fromhex(private_message),
                        asymmetric_padding.OAEP(
                            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
    
                    print("Decrypted message:", decrypted_message.decode())
                    decrypted_message = decrypted_message.decode()
                    # Calcula o hash da mensagem recebida
                    calculated_hash = hashlib.sha256(decrypted_message.encode()).hexdigest()

                    # Verifica se os hashes coincidem
                    if received_hash == calculated_hash:
                        self.display_private_message(f"{sender} to me: {decrypted_message} (Authenticated Message)")
                    else:
                        self.display_private_message(f"{sender} to me: {decrypted_message} (Unauthenticated Message)")
                elif '|' in message:
                    parts = message.split('|')
                    sender = parts[0]
                    received_message = parts[1]
                    received_hash = parts[2]
                    
                    # Calcula o hash da mensagem recebida
                    calculated_hash = hashlib.sha256(received_message.encode()).hexdigest()
                    
                    # Verifica se os hashes coincidem
                    if received_hash == calculated_hash:
                         if self.current_chat == None:  # Exibe apenas se não houver chat privado atual
                            self.display_message(f"{sender}: {received_message} (Authenticated Message)")
                    else:
                         if self.current_chat == None:  # Exibe apenas se não houver chat privado atual
                            self.display_message(f"{sender}: {received_message} (Unauthenticated Message)")
                else:
                    if self.current_chat is None:  # Ignora mensagens do chat global se estiver em um chat privado
                        self.display_message(message)
            except ConnectionResetError:
                print("\nConnection lost.")
                break


    def update_online_users(self, users_str):
        users = users_str.split(',')
        self.online_users = users
        self.online_users_listbox.delete(0, tk.END)
        self.online_users_listbox.insert(tk.END, "Global Chat")  # Adiciona "Global Chat" à lista
        for user in reversed(self.online_users):  # Adiciona o próprio usuário no topo da lista
            if user == self.own_username:  # Destaca o próprio usuário na lista
                self.online_users_listbox.insert(tk.END, f"I'm: {user}")
                # Configura a cor do texto para o usuário atual x cor
                self.online_users_listbox.itemconfigure(tk.END, fg="red")
            else:
                self.online_users_listbox.insert(tk.END, user)

    def setup_chat_ui(self):
        # Interface
        self.online_users_frame = tk.Frame(self.master, width=200, bg="#282828", bd=2, relief=tk.SUNKEN)  # Darker background color, added border and relief
        self.online_users_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.online_users_label = tk.Label(self.online_users_frame, text="Online Users", bg="#282828", fg="#FFFFFF", font=("Helvetica", 14, "bold"))  # Changed font and increased font size
        self.online_users_label.pack(pady=10)

        self.online_users_listbox = tk.Listbox(self.online_users_frame, bg="#383838", fg="#FFFFFF", font=("Helvetica", 12), selectbackground="#484848")  # Adjusted colors
        self.online_users_listbox.pack(fill=tk.BOTH, expand=True)

        # Evento de clique na lista de usuários online
        self.online_users_listbox.bind("<Button-1>", lambda event: self.open_chat(event))

        self.chat_frame = tk.Frame(self.master, bg="#484848")  # Adjusted background color
        self.chat_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Updated layout for chat interface
        self.chat_label = tk.Label(self.chat_frame, text="Global Chat", bg="#484848", fg="#FFFFFF", font=("Helvetica", 16, "bold"))  # Changed font and increased font size
        self.chat_label.pack(pady=(10, 5), padx=10, anchor="nw", fill=tk.X)

        self.chat_text = tk.Text(self.chat_frame, state='disabled', bg="#585858", fg="#FFFFFF", font=("Helvetica", 12))  # Adjusted colors
        self.chat_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.message_entry = tk.Entry(self.chat_frame, font=("Helvetica", 12), bg="#585858", fg="#FFFFFF")  # Adjusted colors
        self.message_entry.insert(tk.END, "Write a message to your friends")
        self.message_entry.bind("<FocusIn>", lambda event: self.clear_entry())
        self.message_entry.bind("<Return>", lambda event: self.send_message(recipient_public_key, event))  # Evento Enter
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=5)

        # Focar automaticamente no campo de entrada de mensagem
        self.message_entry.focus_set()

        # Create a frame to contain the send and close buttons
        button_frame = tk.Frame(self.chat_frame, bg="#484848")
        button_frame.pack(fill=tk.X, padx=10, pady=(5, 10), anchor="se")

        self.send_button = tk.Button(button_frame, text="Send", command=lambda: self.send_message(recipient_public_key, None), bg="#FF5A5F", fg="white", font=("Helvetica", 12, "bold"))  # Adjusted colors
        self.send_button.pack(side=tk.LEFT, padx=(0, 10))

        self.close_button = tk.Button(button_frame, text="Close", command=self.close_application, bg="#FF5A5F", fg="white", font=("Helvetica", 12, "bold"))  # Adjusted colors
        self.close_button.pack(side=tk.LEFT)

        # Adiciona evento para fechar a aplicação e a interface ao pressionar "Esc"
        self.master.bind("<Escape>", lambda event: self.close_application())

    def clear_entry(self):
        if self.message_entry.get() == "Write a message to your friends":
            self.message_entry.delete(0, tk.END)

    def send_message(self, recipient_public_key = None, event=None):  # Adicionando event=None para o evento Enter
        message = self.message_entry.get()
        if message and message != "Write a message to your friends":
            if self.current_chat and recipient_public_key is not None:  # Se houver um chat privado aberto, envie a mensagem apenas para esse usuário
                
                if recipient_public_key:
                    
                    # Deserializar a chave pública
                    recipient_public_key = serialization.load_pem_public_key( 
                        recipient_public_key.encode(), 
                        backend=default_backend()
                    )
                else:
                    print("Recipient's public key not found.")

                # Criptografar a mensagem usando a chave pública
                encrypted_message = recipient_public_key.encrypt(
                    message.encode(),  # Certifique-se de codificar a mensagem para bytes
                    asymmetric_padding.OAEP(
                        mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # Calcula o hash da mensagem
                message_hash = hashlib.sha256(message.encode()).hexdigest()
                self.client_socket.send(f"3|{self.current_chat}|{encrypted_message.hex()}|{message_hash}".encode())
                self.display_private_message(f"I'm to {self.current_chat}: {message}")  # Exibindo a mensagem localmente
            else:
                # Calcula o hash da mensagem
                message_hash = hashlib.sha256(message.encode()).hexdigest()
                self.client_socket.send(f"2|{message}|{message_hash}".encode())
                self.display_message(f"I'm: {message}", align='right')  # Exibindo a mensagem do remetente localmente
            self.message_entry.delete(0, tk.END)

    def display_message(self, message, align='left'):
        if '|' in message:  # Verifica se a mensagem contém um hash
            parts = message.split('|')
            sender = parts[0]
            received_message = parts[1]
            received_hash = parts[2]

            # Calcula o hash da mensagem recebida
            calculated_hash = hashlib.sha256(received_message.encode()).hexdigest()

            # Verifica se os hashes coincidem
            if received_hash == calculated_hash:
                # Se os hashes coincidirem, exibe a mensagem com o nome do remetente e indicação de mensagem fidedigna
                self.chat_text.configure(state='normal')
                self.chat_text.insert(tk.END, f"{sender}: {received_message} (Authenticated Message)\n")
                self.chat_text.configure(state='disabled')
            else:
                # Se os hashes não coincidirem, exibe a mensagem com o nome do remetente e indicação de mensagem não fidedigna
                self.chat_text.configure(state='normal')
                self.chat_text.insert(tk.END, f"{sender}: {received_message} (Unauthenticated Message)\n")
                self.chat_text.configure(state='disabled')
        else:
            # Se a mensagem não contiver um hash, exibe como antes
            self.chat_text.configure(state='normal')
            self.chat_text.insert(tk.END, f"{message}\n")
            self.chat_text.configure(state='disabled')

    def display_private_message(self, message):
        self.chat_text.configure(state='normal')
        self.chat_text.insert(tk.END, message + '\n')
        self.chat_text.configure(state='disabled')

    def close_application(self, event=None):
        self.client_socket.close()  # Fecha o socket do cliente
        self.master.destroy()

    def open_chat(self, event):
        # Verifica o item selecionado na lista de usuários online
        index = self.online_users_listbox.nearest(event.y)
        selected_user = self.online_users_listbox.get(index)

        # Evitar seleção do próprio nome
        if selected_user.startswith("I'm:"):
            return
        if selected_user == "Global Chat":
            self.current_chat = None
            self.chat_label.config(text="Global Chat")
            self.chat_text.configure(state='normal')
            self.chat_text.delete(1.0, tk.END)
            self.chat_text.configure(state='disabled')
        elif selected_user:
            # Se o usuário selecionado não for o "Global Chat", abre um chat privado
            self.setup_private_chat(selected_user)

    def setup_private_chat(self, selected_user):
        if selected_user not in self.private_chats:
            self.current_chat = selected_user
        # Limpa o chat global
        self.chat_text.configure(state='normal')
        self.chat_text.delete(1.0, tk.END)
        self.chat_text.configure(state='disabled')

        # Atualiza a etiqueta do chat para exibir o nome do usuário selecionado
        self.chat_label.config(text=f"Chat with {selected_user}")

        # Exibir as mensagens de chat privado
        self.client_socket.send(f"4|{selected_user}".encode())

        # Carrega a chave pública do destinatário
        global recipient_public_key
        recipient_public_key = self.load_recipient_public_key(selected_user)

        return recipient_public_key


    def load_recipient_public_key(self, selected_user):
        # Carrega as chaves públicas
        public_keys = self.load_public_keys()
        if selected_user in public_keys:
            return public_keys[selected_user]
        else:
            return None

def main():
    root = tk.Tk()
    app = ChatApplication(root)
    window_width = 800
    window_height = 600
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x_coordinate = (screen_width - window_width) // 2
    y_coordinate = (screen_height - window_height) // 2
    root.geometry(f"{window_width}x{window_height}+{x_coordinate}+{y_coordinate}")
    root.mainloop()

if __name__ == "__main__":
    main()
