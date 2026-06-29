from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# --------------------------------------------------------------------------- #
# Identity keys
# --------------------------------------------------------------------------- #
def generate_keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def serialize_public_key(public_key: rsa.RSAPublicKey) -> str:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")


def load_public_key(pem: str) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(pem.encode("utf-8"))


def fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """Short human-verifiable fingerprint (guards against key-swap MITM)."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(raw)
    fp = digest.finalize().hex()
    return ":".join(fp[i:i + 4] for i in range(0, 16, 4))  # first 16 hex chars


# --------------------------------------------------------------------------- #
# Hybrid message encryption
# --------------------------------------------------------------------------- #
@dataclass
class EncryptedBundle:
    wrapped_key: str   # base64: AES key encrypted with recipient RSA public key
    nonce: str         # base64: AES-GCM nonce
    ciphertext: str    # base64: AES-GCM ciphertext (+ auth tag)

    def to_json(self) -> str:
        return json.dumps({
            "wrapped_key": self.wrapped_key,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
        })

    @staticmethod
    def from_json(s: str) -> "EncryptedBundle":
        d = json.loads(s)
        return EncryptedBundle(d["wrapped_key"], d["nonce"], d["ciphertext"])


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def encrypt_message(plaintext: str, recipient_public_key: rsa.RSAPublicKey) -> EncryptedBundle:
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), None)

    wrapped = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return EncryptedBundle(_b64e(wrapped), _b64e(nonce), _b64e(ciphertext))


def decrypt_message(bundle: EncryptedBundle, private_key: rsa.RSAPrivateKey) -> str:
    aes_key = private_key.decrypt(
        _b64d(bundle.wrapped_key),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    plaintext = AESGCM(aes_key).decrypt(
        _b64d(bundle.nonce), _b64d(bundle.ciphertext), None
    )
    return plaintext.decode("utf-8")
