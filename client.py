"""
client.py
---------
CryptoChat client. Generates an RSA identity, learns peers' public keys from
the server roster, and sends end-to-end-encrypted messages.

Usage:
    python -m cryptochat.client --name Rimon --host 127.0.0.1 --port 9001

Commands inside the chat:
    @alice hello there     -> send encrypted message to 'alice'
    /peers                 -> list connected peers and key fingerprints
    /quit                  -> exit
"""

from __future__ import annotations

import argparse
import socket
import threading
from typing import Dict

from cryptochat.crypto import (
    generate_keypair, serialize_public_key, load_public_key,
    encrypt_message, decrypt_message, fingerprint, EncryptedBundle,
)
from cryptochat.protocol import send_frame, recv_frame


class ChatClient:
    def __init__(self, name: str, host: str, port: int):
        self.name = name
        self.host = host
        self.port = port
        self.private_key = generate_keypair()
        self.public_pem = serialize_public_key(self.private_key.public_key())
        self.peers: Dict[str, str] = {}     # name -> pubkey pem
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self) -> None:
        self.sock.connect((self.host, self.port))
        send_frame(self.sock, {"type": "join", "name": self.name,
                               "pubkey": self.public_pem})
        my_fp = fingerprint(self.private_key.public_key())
        print(f"[*] Connected as '{self.name}'. Your key fingerprint: {my_fp}")
        print("[*] Type '@name message' to send, '/peers' to list, '/quit' to exit.\n")
        threading.Thread(target=self._receive_loop, daemon=True).start()

    def _receive_loop(self) -> None:
        while True:
            frame = recv_frame(self.sock)
            if frame is None:
                print("\n[!] Disconnected from server.")
                break
            t = frame.get("type")
            if t == "roster":
                self.peers = {p["name"]: p["pubkey"] for p in frame["peers"]
                              if p["name"] != self.name}
            elif t == "relay":
                self._handle_incoming(frame)
            elif t == "error":
                print(f"[!] Server error: {frame.get('message')}")

    def _handle_incoming(self, frame: dict) -> None:
        sender = frame.get("sender")
        try:
            bundle = EncryptedBundle.from_json(frame["bundle"])
            text = decrypt_message(bundle, self.private_key)
            print(f"\n[{sender}] {text}")
        except Exception:
            print(f"\n[!] Failed to decrypt message from {sender} "
                  f"(corrupt or not addressed to you).")

    def send_to(self, recipient: str, text: str) -> None:
        pem = self.peers.get(recipient)
        if pem is None:
            print(f"[!] Unknown peer '{recipient}'. Try /peers.")
            return
        bundle = encrypt_message(text, load_public_key(pem))
        send_frame(self.sock, {"type": "relay", "sender": self.name,
                               "recipient": recipient, "bundle": bundle.to_json()})

    def list_peers(self) -> None:
        if not self.peers:
            print("[*] No other peers connected.")
            return
        print("[*] Connected peers:")
        for name, pem in self.peers.items():
            fp = fingerprint(load_public_key(pem))
            print(f"    {name:<12} fingerprint {fp}")

    def repl(self) -> None:
        try:
            while True:
                line = input()
                if not line:
                    continue
                if line == "/quit":
                    break
                if line == "/peers":
                    self.list_peers()
                    continue
                if line.startswith("@"):
                    parts = line[1:].split(" ", 1)
                    if len(parts) == 2:
                        self.send_to(parts[0], parts[1])
                    else:
                        print("[!] Usage: @name your message")
                    continue
                print("[!] Start with @name to send, or use /peers, /quit.")
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            self.sock.close()


def main() -> None:
    p = argparse.ArgumentParser(description="CryptoChat client")
    p.add_argument("--name", required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9001)
    args = p.parse_args()
    client = ChatClient(args.name, args.host, args.port)
    client.connect()
    client.repl()


if __name__ == "__main__":
    main()
