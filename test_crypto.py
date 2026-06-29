import sys, os, base64
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptochat.crypto import (
    generate_keypair, serialize_public_key, load_public_key,
    encrypt_message, decrypt_message, EncryptedBundle, fingerprint,
)


def test_roundtrip():
    priv = generate_keypair()
    pub = priv.public_key()
    msg = "Hello from Morioka 盛岡 — secret message!"
    bundle = encrypt_message(msg, pub)
    out = decrypt_message(bundle, priv)
    assert out == msg, "round-trip mismatch"
    print("PASS: encrypt/decrypt round-trip (incl. unicode)")


def test_public_key_serialization():
    priv = generate_keypair()
    pem = serialize_public_key(priv.public_key())
    restored = load_public_key(pem)
    msg = "via serialized key"
    out = decrypt_message(encrypt_message(msg, restored), priv)
    assert out == msg
    print("PASS: public key survives PEM serialize/deserialize")


def test_wrong_key_fails():
    priv_a = generate_keypair()
    priv_b = generate_keypair()
    bundle = encrypt_message("for A only", priv_a.public_key())
    try:
        decrypt_message(bundle, priv_b)
        assert False, "decryption with wrong key should fail"
    except Exception:
        print("PASS: wrong private key cannot decrypt")


def test_tamper_detected():
    priv = generate_keypair()
    bundle = encrypt_message("integrity test", priv.public_key())
    # Flip a byte in the ciphertext.
    raw = bytearray(base64.b64decode(bundle.ciphertext))
    raw[0] ^= 0x01
    tampered = EncryptedBundle(bundle.wrapped_key, bundle.nonce,
                               base64.b64encode(bytes(raw)).decode())
    try:
        decrypt_message(tampered, priv)
        assert False, "tampered ciphertext should be rejected"
    except Exception:
        print("PASS: AES-GCM detected tampering and rejected message")


def test_fingerprint_stable():
    priv = generate_keypair()
    fp1 = fingerprint(priv.public_key())
    pem = serialize_public_key(priv.public_key())
    fp2 = fingerprint(load_public_key(pem))
    assert fp1 == fp2
    print("PASS: key fingerprint is stable ->", fp1)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print(f"\nAll {len(tests)} tests passed.")
