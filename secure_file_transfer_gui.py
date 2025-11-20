"""
Secure File Transfer - GUI Version
Contains two GUI apps in one file for convenience:
 - server_gui: Start/stop the server, view logs
 - client_gui: Select file, set server host/port, send file, view ACK

Usage (run two instances or run server on one machine and client on another):
    python secure_file_transfer_gui.py server
    python secure_file_transfer_gui.py client

Dependencies:
    pip install cryptography

This code is intended for educational/demo use only.
"""

import os
import sys
import json
import socket
import struct
import threading
import queue
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ----------------------------- Shared crypto/network helpers -----------------------------

def recvn(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Connection closed while receiving")
        data += packet
    return data

# ----------------------------- Server implementation (background thread) -----------------------------

class ServerThread(threading.Thread):
    def __init__(self, host, port, rsa_priv_path, recv_dir, log_queue, stop_event):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.rsa_priv_path = rsa_priv_path
        self.recv_dir = recv_dir
        self.log_queue = log_queue
        self.stop_event = stop_event
        self.sock = None

    def log(self, *parts):
        self.log_queue.put(" ".join(map(str, parts)))

    def load_or_create_rsa_private(self, path: str):
        if os.path.exists(path):
            with open(path, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        # create new RSA key
        from cryptography.hazmat.primitives.asymmetric import rsa
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(path, "wb") as f:
            f.write(pem)
        self.log(f"Generated RSA private key -> {path}")
        return private_key

    def handle_client(self, conn, addr, private_key):
        self.log(f"[+] Connection from {addr}")
        # 1) Read 4-byte header length
        raw = recvn(conn, 4)
        header_len = struct.unpack("!I", raw)[0]
        header_bytes = recvn(conn, header_len)
        header = json.loads(header_bytes.decode())
        filename = os.path.basename(header.get("filename", "received.bin"))
        enc_key_len = header["enc_key_len"]
        nonce_len = header["nonce_len"]
        ciphertext_len = header["ciphertext_len"]

        enc_key = recvn(conn, enc_key_len)
        nonce = recvn(conn, nonce_len)
        ciphertext = recvn(conn, ciphertext_len)

        # Decrypt symmetric key using RSA-OAEP
        try:
            sym_key = private_key.decrypt(
                enc_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(),
                             label=None)
            )
        except Exception as e:
            self.log(f"[!] Failed to decrypt symmetric key: {e}")
            conn.close()
            return

        # Decrypt ciphertext using AES-GCM
        aesgcm = AESGCM(sym_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        except Exception as e:
            self.log(f"[!] Decryption failed: {e}")
            conn.close()
            return

        os.makedirs(self.recv_dir, exist_ok=True)
        out_path = os.path.join(self.recv_dir, filename)
        with open(out_path, "wb") as f:
            f.write(plaintext)

        digest = hashes.Hash(hashes.SHA256())
        digest.update(plaintext)
        sha256_hex = digest.finalize().hex()

        self.log(f"[+] Received and decrypted '{filename}' -> saved to '{out_path}' (sha256: {sha256_hex})")
        # send ack
        ack = json.dumps({"status":"ok","sha256":sha256_hex}).encode()
        try:
            conn.sendall(struct.pack("!I", len(ack)) + ack)
        except Exception:
            pass
        conn.close()

    def run(self):
        private_key = self.load_or_create_rsa_private(self.rsa_priv_path)
        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_path = os.path.splitext(self.rsa_priv_path)[0] + "_public.pem"
        with open(pub_path, "wb") as f:
            f.write(pub_pem)
        self.log(f"Server public key written to {pub_path}")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(5)
            s.settimeout(1.0)
            self.sock = s
            self.log(f"Listening on {self.host}:{self.port} ...")
            while not self.stop_event.is_set():
                try:
                    conn, addr = s.accept()
                    # handle each client in its own thread so server UI stays responsive
                    t = threading.Thread(target=self.handle_client, args=(conn, addr, private_key), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    self.log(f"[!] Server error: {e}")
                    break
            self.log("Server stopping...")

# ----------------------------- Client implementation (background thread) -----------------------------

class ClientThread(threading.Thread):
    def __init__(self, server_host, server_port, filepath, pubkey_path, result_queue):
        super().__init__(daemon=True)
        self.server_host = server_host
        self.server_port = int(server_port)
        self.filepath = filepath
        self.pubkey_path = pubkey_path
        self.result_queue = result_queue

    def load_server_public_key(self, path="server_public_key.pem"):
        with open(path, "rb") as f:
            return serialization.load_pem_public_key(f.read())

    def run(self):
        try:
            with open(self.filepath, "rb") as f:
                plaintext = f.read()
        except Exception as e:
            self.result_queue.put((False, f"Failed to read file: {e}"))
            return

        # generate symmetric key and encrypt using AES-GCM
        aes_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

        # load server public key and encrypt AES key using RSA-OAEP
        try:
            pub = self.load_server_public_key(self.pubkey_path)
        except Exception as e:
            self.result_queue.put((False, f"Failed to load server public key: {e}"))
            return

        try:
            enc_key = pub.encrypt(
                aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(),
                             label=None)
            )
        except Exception as e:
            self.result_queue.put((False, f"RSA encrypt failed: {e}"))
            return

        header = {
            "filename": os.path.basename(self.filepath),
            "enc_key_len": len(enc_key),
            "nonce_len": len(nonce),
            "ciphertext_len": len(ciphertext)
        }
        header_bytes = json.dumps(header).encode()

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.server_host, self.server_port))
                s.sendall(struct.pack("!I", len(header_bytes)))
                s.sendall(header_bytes)
                s.sendall(enc_key)
                s.sendall(nonce)
                s.sendall(ciphertext)

                # receive ack
                raw_len = recvn(s, 4)
                l = struct.unpack("!I", raw_len)[0]
                payload = recvn(s, l)
                ack = json.loads(payload.decode())
                self.result_queue.put((True, ack))
        except Exception as e:
            self.result_queue.put((False, f"Network/send failed: {e}"))

# ----------------------------- Tkinter GUI for Server -----------------------------

class ServerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Secure Transfer - Server")
        self.log_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.server_thread = None

        frm = ttk.Frame(root, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        row = 0
        ttk.Label(frm, text="Host:").grid(column=0, row=row, sticky=tk.W)
        self.host_var = tk.StringVar(value="0.0.0.0")
        ttk.Entry(frm, textvariable=self.host_var, width=15).grid(column=1, row=row, sticky=tk.W)

        ttk.Label(frm, text="Port:").grid(column=2, row=row, sticky=tk.W)
        self.port_var = tk.StringVar(value="9000")
        ttk.Entry(frm, textvariable=self.port_var, width=7).grid(column=3, row=row, sticky=tk.W)

        row += 1
        ttk.Label(frm, text="RSA private key path:").grid(column=0, row=row, sticky=tk.W)
        self.priv_path_var = tk.StringVar(value="server_private_key.pem")
        ttk.Entry(frm, textvariable=self.priv_path_var, width=40).grid(column=1, row=row, columnspan=3, sticky=tk.W)

        row += 1
        ttk.Label(frm, text="Receive dir:").grid(column=0, row=row, sticky=tk.W)
        self.recv_dir_var = tk.StringVar(value="received_files")
        ttk.Entry(frm, textvariable=self.recv_dir_var, width=40).grid(column=1, row=row, columnspan=3, sticky=tk.W)

        row += 1
        self.start_btn = ttk.Button(frm, text="Start Server", command=self.start_server)
        self.start_btn.grid(column=0, row=row, sticky=tk.W)
        self.stop_btn = ttk.Button(frm, text="Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.stop_btn.grid(column=1, row=row, sticky=tk.W)

        row += 1
        ttk.Label(frm, text="Logs:").grid(column=0, row=row, sticky=tk.W)
        row += 1
        self.log_text = tk.Text(frm, width=80, height=20, state=tk.DISABLED)
        self.log_text.grid(column=0, row=row, columnspan=4, sticky=tk.NSEW)

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._poll_logs()

    def start_server(self):
        host = self.host_var.get()
        port = int(self.port_var.get())
        priv = self.priv_path_var.get()
        recv_dir = self.recv_dir_var.get()
        self.stop_event.clear()
        self.server_thread = ServerThread(host, port, priv, recv_dir, self.log_queue, self.stop_event)
        self.server_thread.start()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

    def stop_server(self):
        self.stop_event.set()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def _poll_logs(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.log_text.config(state=tk.NORMAL)
                self.log_text.insert(tk.END, msg + "\n")
                self.log_text.see(tk.END)
                self.log_text.config(state=tk.DISABLED)
        except queue.Empty:
            pass
        self.root.after(200, self._poll_logs)

    def on_close(self):
        if messagebox.askokcancel("Quit", "Stop server and quit?"):
            self.stop_event.set()
            self.root.destroy()

# ----------------------------- Tkinter GUI for Client -----------------------------

class ClientGUI:
    def __init__(self, root):
        self.root = root
        root.title("Secure Transfer - Client")
        self.result_queue = queue.Queue()

        frm = ttk.Frame(root, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        row = 0
        ttk.Label(frm, text="Server Host:").grid(column=0, row=row, sticky=tk.W)
        self.host_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(frm, textvariable=self.host_var, width=20).grid(column=1, row=row, sticky=tk.W)

        ttk.Label(frm, text="Port:").grid(column=2, row=row, sticky=tk.W)
        self.port_var = tk.StringVar(value="9000")
        ttk.Entry(frm, textvariable=self.port_var, width=7).grid(column=3, row=row, sticky=tk.W)

        row += 1
        ttk.Label(frm, text="Server public key path:").grid(column=0, row=row, sticky=tk.W)
        self.pub_path_var = tk.StringVar(value="server_public_key.pem")
        ttk.Entry(frm, textvariable=self.pub_path_var, width=40).grid(column=1, row=row, columnspan=3, sticky=tk.W)

        row += 1
        ttk.Label(frm, text="File to send:").grid(column=0, row=row, sticky=tk.W)
        self.file_var = tk.StringVar(value="")
        ttk.Entry(frm, textvariable=self.file_var, width=40).grid(column=1, row=row, columnspan=2, sticky=tk.W)
        ttk.Button(frm, text="Browse...", command=self.browse_file).grid(column=3, row=row, sticky=tk.W)

        row += 1
        self.send_btn = ttk.Button(frm, text="Send File", command=self.send_file)
        self.send_btn.grid(column=0, row=row, sticky=tk.W)

        row += 1
        ttk.Label(frm, text="Result / ACK:").grid(column=0, row=row, sticky=tk.W)
        row += 1
        self.result_text = tk.Text(frm, width=80, height=10, state=tk.DISABLED)
        self.result_text.grid(column=0, row=row, columnspan=4, sticky=tk.NSEW)

        self._poll_result()

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_var.set(path)

    def send_file(self):
        filepath = self.file_var.get()
        if not filepath or not os.path.exists(filepath):
            messagebox.showerror("Error", "Please choose an existing file to send")
            return
        pub = self.pub_path_var.get()
        if not os.path.exists(pub):
            messagebox.showerror("Error", f"Server public key not found: {pub}")
            return
        self.send_btn.config(state=tk.DISABLED)
        t = ClientThread(self.host_var.get(), self.port_var.get(), filepath, pub, self.result_queue)
        t.start()

    def _poll_result(self):
        try:
            while True:
                ok, payload = self.result_queue.get_nowait()
                self.result_text.config(state=tk.NORMAL)
                if ok:
                    self.result_text.insert(tk.END, f"Success: {json.dumps(payload)}\n")
                else:
                    self.result_text.insert(tk.END, f"Error: {payload}\n")
                self.result_text.see(tk.END)
                self.result_text.config(state=tk.DISABLED)
                self.send_btn.config(state=tk.NORMAL)
        except queue.Empty:
            pass
        self.root.after(200, self._poll_result)

# ----------------------------- Main entry: choose server or client -----------------------------

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("server", "client"):
        print("Usage: python secure_file_transfer_gui.py [server|client]")
        sys.exit(1)

    mode = sys.argv[1]
    root = tk.Tk()
    if mode == "server":
        app = ServerGUI(root)
    else:
        app = ClientGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
