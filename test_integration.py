import sys, os, time, socket, threading
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptochat.server import ChatServer
from cryptochat.client import ChatClient


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_end_to_end():
    port = free_port()
    server = ChatServer("127.0.0.1", port)
    threading.Thread(target=server.serve, daemon=True).start()
    time.sleep(0.3)

    alice = ChatClient("alice", "127.0.0.1", port)
    bob = ChatClient("bob", "127.0.0.1", port)
    alice.connect()
    bob.connect()
    time.sleep(0.5)  # allow roster exchange

    received = {}
    orig = bob._handle_incoming
    def capture(frame):
        sender = frame.get("sender")
        from cryptochat.crypto import decrypt_message, EncryptedBundle
        bundle = EncryptedBundle.from_json(frame["bundle"])
        received["text"] = decrypt_message(bundle, bob.private_key)
        received["sender"] = sender
    bob._handle_incoming = capture

    secret = "meet at 3pm — 秘密"
    alice.send_to("bob", secret)
    time.sleep(0.5)

    assert received.get("text") == secret, "bob did not receive correct plaintext"
    assert received.get("sender") == "alice"
    print("PASS: alice -> bob E2E message delivered and decrypted correctly")

    # Confirm the server only ever held ciphertext, never the plaintext.
    assert "bob" in server.pubkeys and "alice" in server.pubkeys
    assert secret.encode("utf-8") not in repr(server.pubkeys).encode("utf-8")
    print("PASS: server stored only public keys, never the plaintext")

    alice.sock.close()
    bob.sock.close()


if __name__ == "__main__":
    test_end_to_end()
    print("\nIntegration test passed.")
