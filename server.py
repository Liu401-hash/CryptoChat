from __future__ import annotations

import argparse
import socket
import threading
from typing import Dict

from cryptochat.protocol import send_frame, recv_frame


class ChatServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.clients: Dict[str, socket.socket] = {}   # name -> socket
        self.pubkeys: Dict[str, str] = {}             # name -> pem
        self.lock = threading.Lock()

    def broadcast_roster(self) -> None:
        with self.lock:
            peers = [{"name": n, "pubkey": self.pubkeys[n]} for n in self.clients]
            targets = list(self.clients.values())
        for sock in targets:
            try:
                send_frame(sock, {"type": "roster", "peers": peers})
            except OSError:
                pass

    def handle_client(self, sock: socket.socket, addr) -> None:
        name = None
        try:
            join = recv_frame(sock)
            if not join or join.get("type") != "join":
                return
            name = join["name"]
            with self.lock:
                if name in self.clients:
                    send_frame(sock, {"type": "error",
                                      "message": "name already in use"})
                    return
                self.clients[name] = sock
                self.pubkeys[name] = join["pubkey"]
            print(f"[+] {name} joined from {addr[0]}:{addr[1]}")
            self.broadcast_roster()

            while True:
                frame = recv_frame(sock)
                if frame is None:
                    break
                if frame.get("type") == "relay":
                    self._relay(frame)
        except (OSError, KeyError):
            pass
        finally:
            if name:
                with self.lock:
                    self.clients.pop(name, None)
                    self.pubkeys.pop(name, None)
                print(f"[-] {name} disconnected")
                self.broadcast_roster()
            sock.close()

    def _relay(self, frame: dict) -> None:
        recipient = frame.get("recipient")
        with self.lock:
            target = self.clients.get(recipient)
        if target is not None:
            try:
                send_frame(target, frame)   # opaque ciphertext, untouched
            except OSError:
                pass

    def serve(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen()
        print(f"[*] CryptoChat relay listening on {self.host}:{self.port}")
        print("[*] Server relays ciphertext only - it cannot read messages.")
        try:
            while True:
                conn, addr = srv.accept()
                threading.Thread(target=self.handle_client,
                                 args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[*] Shutting down.")
        finally:
            srv.close()


def main() -> None:
    p = argparse.ArgumentParser(description="CryptoChat relay server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=9001)
    args = p.parse_args()
    ChatServer(args.host, args.port).serve()


if __name__ == "__main__":
    main()
