# CryptoChat — End-to-End Encrypted Chat

A client–server chat application where messages are **end-to-end encrypted**:
the relay server forwards only ciphertext and can never read message contents.
Built in Python using hybrid RSA + AES-GCM encryption.

CryptoChat demonstrates **applied cryptography** (hybrid encryption, authenticated
encryption, key management) and **secure network protocol design** (a
zero-knowledge relay over raw TCP sockets).

---

## Security design

CryptoChat uses **hybrid encryption**, the same pattern used by real messaging
systems:

- **Identity** — each client generates an RSA-2048 keypair on startup. The
  private key never leaves the client.
- **Key exchange** — clients publish their *public* key to the server, which
  distributes a roster of peers and their public keys.
- **Per-message secrecy** — for every message, the sender generates a fresh
  **AES-256-GCM** key, encrypts the message body with it, and wraps that AES key
  with the recipient's **RSA public key (OAEP-SHA256)**. Only the recipient's
  private key can unwrap it.
- **Integrity & authenticity** — AES-GCM produces an authentication tag, so any
  tampering with the ciphertext is detected and the message is rejected.
- **Key-swap defense** — each public key has a short SHA-256 **fingerprint** that
  users can verify out-of-band to detect a malicious server swapping keys (MITM).

Because the server only ever holds public keys and opaque ciphertext, it is a
**zero-knowledge relay** — trust is not placed in the server.

## Architecture

```
   alice                    server (relay)                     bob
   -----                    --------------                     ---
   RSA keypair              knows only:                        RSA keypair
      |                       - names                              |
      | join + pubkey  --->   - public keys      <--- join + pubkey|
      |                       - ciphertext                         |
      |                                                            |
      | encrypt(msg, bob_pub) --> relay (opaque) --> decrypt(priv) |
      |                                                            |
   plaintext never leaves endpoints; server cannot decrypt.
```

## Wire protocol

Length-prefixed JSON framing (4-byte big-endian length + UTF-8 JSON body) so
messages are never split or merged on the TCP stream. Message types: `join`,
`roster`, `relay`, `error`.

## Installation

```bash
git clone https://github.com/<you>/cryptochat.git
cd cryptochat
pip install -r requirements.txt
```

## Usage

Start the relay server:

```bash
python -m cryptochat.server --host 0.0.0.0 --port 9001
```

Start one or more clients (separate terminals):

```bash
python -m cryptochat.client --name alice --host 127.0.0.1 --port 9001
python -m cryptochat.client --name bob   --host 127.0.0.1 --port 9001
```

In-chat commands:

```
@bob hello there      send an encrypted message to bob
/peers                list connected peers and key fingerprints
/quit                 exit
```

## Testing

```bash
python tests/test_crypto.py        # crypto round-trip, tamper detection, key isolation
python tests/test_integration.py   # real server + two clients over sockets
```

The integration test asserts that bob decrypts alice's message correctly **and**
that the server stored only public keys, never the plaintext.

## Threat model & limitations

CryptoChat protects message confidentiality and integrity against a passive or
malicious relay. It does **not** implement forward secrecy (a per-session
ephemeral key-agreement like X3DH/Double Ratchet would add this) and relies on
out-of-band fingerprint verification to fully defeat an active MITM. It is an
educational project, not a substitute for an audited messenger.

## Tech stack

Python 3 · `cryptography` (RSA-OAEP, AES-256-GCM) · sockets · threading

## License

MIT
