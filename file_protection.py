import os
import hashlib
import secrets
import base64
import json
from pathlib import Path

# ──────────────────────────────────────────────
#  FILE PROTECTION UTILITY
#  - Encrypt: converts file → protected .enc file
#  - Decrypt: restores .enc file → original file
#  Uses XOR stream cipher with PBKDF2 key derivation
# ──────────────────────────────────────────────

MAGIC_HEADER = b"FPU_PROTECTED_v1"


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a strong key from password + salt using PBKDF2-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations=100_000)


def xor_cipher(data: bytes, key: bytes) -> bytes:
    """XOR stream cipher - key is repeated over full data length."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def encrypt_file(input_path: str, password: str) -> str:
    """
    Encrypt a file and save as <filename>.enc

    Args:
        input_path: Path to the file to encrypt
        password:   Password for protection

    Returns:
        Path to the encrypted .enc file
    """
    input_path = Path(input_path)
    if not input_path.exists():
        raise FileNotFoundError(f"File not found: {input_path}")

    with open(input_path, "rb") as f:
        original_data = f.read()

    salt = secrets.token_bytes(32)
    iv   = secrets.token_bytes(16)
    key  = derive_key(password, salt)

    encrypted_data = xor_cipher(original_data, key + iv)

    metadata = {
        "original_filename": input_path.name,
        "original_size": len(original_data),
        "salt": base64.b64encode(salt).decode(),
        "iv":   base64.b64encode(iv).decode(),
    }
    metadata_bytes = json.dumps(metadata).encode()
    metadata_len   = len(metadata_bytes).to_bytes(4, "big")

    output_path = input_path.with_suffix(input_path.suffix + ".enc")
    with open(output_path, "wb") as f:
        f.write(MAGIC_HEADER)
        f.write(metadata_len)
        f.write(metadata_bytes)
        f.write(encrypted_data)

    return str(output_path)


def decrypt_file(enc_path: str, password: str, output_dir: str = None) -> str:
    """
    Decrypt a .enc file and restore the original.

    Args:
        enc_path:   Path to the .enc file
        password:   Password used during encryption
        output_dir: Where to save the restored file (default: same folder)

    Returns:
        Path to the restored file
    """
    enc_path = Path(enc_path)
    if not enc_path.exists():
        raise FileNotFoundError(f"Encrypted file not found: {enc_path}")

    with open(enc_path, "rb") as f:
        raw = f.read()

    if not raw.startswith(MAGIC_HEADER):
        raise ValueError("Invalid or corrupted encrypted file.")

    offset       = len(MAGIC_HEADER)
    metadata_len = int.from_bytes(raw[offset:offset + 4], "big")
    offset      += 4
    metadata     = json.loads(raw[offset:offset + metadata_len].decode())
    offset      += metadata_len
    encrypted_data = raw[offset:]

    salt = base64.b64decode(metadata["salt"])
    iv   = base64.b64decode(metadata["iv"])
    key  = derive_key(password, salt)

    decrypted_data = xor_cipher(encrypted_data, key + iv)

    if len(decrypted_data) != metadata["original_size"]:
        raise ValueError("Decryption failed: wrong password or corrupted file.")

    out_dir     = Path(output_dir) if output_dir else enc_path.parent
    output_path = out_dir / metadata["original_filename"]
    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    return str(output_path)


# ──────────────────────────────────────────────
#  CLI INTERFACE
# ──────────────────────────────────────────────

def get_password(confirm: bool = False) -> str:
    import getpass
    while True:
        pwd = getpass.getpass("  Enter password: ")
        if not pwd:
            print("  Password cannot be empty. Try again.")
            continue
        if confirm:
            pwd2 = getpass.getpass("  Confirm password: ")
            if pwd != pwd2:
                print("  Passwords do not match. Try again.")
                continue
        return pwd


def main():
    print("=" * 55)
    print("        File Protection Utility")
    print("=" * 55)
    print("  [1] Encrypt a file")
    print("  [2] Decrypt a file")
    print("  [3] Exit\n")

    choice = input("  Enter choice (1/2/3): ").strip()

    if choice == "1":
        path = input("\n  File to encrypt: ").strip()
        password = get_password(confirm=True)
        try:
            out = encrypt_file(path, password)
            print(f"\n  File encrypted successfully!")
            print(f"  Saved as: {out}")
            print(f"  Original file is untouched.")
        except Exception as e:
            print(f"\n  Error: {e}")

    elif choice == "2":
        path    = input("\n  Encrypted .enc file to decrypt: ").strip()
        out_dir = input("  Output directory (Enter = same folder): ").strip() or None
        password = get_password(confirm=False)
        try:
            out = decrypt_file(path, password, out_dir)
            print(f"\n  File decrypted successfully!")
            print(f"  Restored as: {out}")
        except Exception as e:
            print(f"\n  Error: {e}")

    elif choice == "3":
        print("\n  Goodbye!")
    else:
        print("\n  Invalid choice.")


if __name__ == "__main__":
    main()