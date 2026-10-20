
import json
import time
import secrets
import hmac
import hashlib
import streamlit as st

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def generate_keys():
    return secrets.token_bytes(32), secrets.token_bytes(32)


def encrypt_file(data, filename, aes_key, hmac_key):
    iv = secrets.token_bytes(16)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    metadata = json.dumps({
        "version": 1, "filename": filename
    }, sort_keys=True, separators=(",", ":")).encode()

    message = (b"PFPS-v1" + len(metadata).to_bytes(4, "big")
               + metadata + iv + ciphertext)
    tag = hmac.new(hmac_key, message, hashlib.sha256).digest()

    package = {
        "version": 1,
        "metadata": metadata.hex(),
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex()
    }
    return json.dumps(package).encode()


def decrypt_file(package_data, aes_key, hmac_key):
    package = json.loads(package_data.decode())

    if package.get("version") != 1:
        raise ValueError("Unsupported file format.")

    metadata = bytes.fromhex(package["metadata"])
    iv = bytes.fromhex(package["iv"])
    ciphertext = bytes.fromhex(package["ciphertext"])
    tag = bytes.fromhex(package["tag"])

    message = (b"PFPS-v1" + len(metadata).to_bytes(4, "big")
               + metadata + iv + ciphertext)
    expected_tag = hmac.new(
        hmac_key, message, hashlib.sha256
    ).digest()

    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError(
            "The key does not match this file, or the file was modified."
        )

    if len(iv) != 16 or len(aes_key) != 32:
        raise ValueError("Invalid key or encrypted file.")

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()

    filename = json.loads(metadata.decode())["filename"]
    return data, filename


# Main interface
st.set_page_config(page_title="Personal File Protection", page_icon="🔐")
st.title("Personal File Protection")
st.write("Encrypt and recover your files securely.")

if "encrypted" not in st.session_state:
    st.session_state.encrypted = None
if "recovered" not in st.session_state:
    st.session_state.recovered = None

choice = st.radio("Choose operation",
                  ["Encrypt File", "Decrypt File"],
                  horizontal=True)

if choice == "Encrypt File":
    uploaded = st.file_uploader("Choose a file", key="original")

    if st.button("Encrypt", disabled=uploaded is None):
        try:
            aes_key, hmac_key = generate_keys()

            start = time.perf_counter()
            package = encrypt_file(
                uploaded.getvalue(), uploaded.name, aes_key, hmac_key
            )
            elapsed = time.perf_counter() - start

            keys = json.dumps({
                "aes_key": aes_key.hex(),
                "hmac_key": hmac_key.hex()
            }, indent=2).encode()

            st.session_state.encrypted = {
                "package": package,
                "keys": keys,
                "file_name": uploaded.name + ".pfp",
                "key_name": uploaded.name + ".keys.json",
                "time": elapsed
            }
        except Exception as e:
            st.session_state.encrypted = None
            st.error(f"Encryption failed: {type(e).__name__}: {e}")

    result = st.session_state.encrypted

    if result:
        st.success("File encrypted successfully.")
        st.write(f"Encryption time: {result['time']:.4f} seconds")

        st.download_button(
            "Download encrypted file",
            result["package"],
            file_name=result["file_name"]
        )

        st.download_button(
            "Download secret keys",
            result["keys"],
            file_name=result["key_name"]
        )

        st.warning("Keep the key file safe. You need it to decrypt the file.")

else:
    encrypted = st.file_uploader(
        "Choose encrypted file (.pfp)", type=["pfp"], key="encrypted"
    )
    key_file = st.file_uploader(
        "Choose matching key file (.json)", type=["json"], key="keys"
    )

    if st.button("Verify and Decrypt",
                 disabled=encrypted is None or key_file is None):
        try:
            keys = json.loads(key_file.getvalue().decode())
            aes_key = bytes.fromhex(keys["aes_key"])
            hmac_key = bytes.fromhex(keys["hmac_key"])

            if len(aes_key) != 32 or len(hmac_key) != 32:
                raise ValueError("Invalid key length.")

            start = time.perf_counter()
            data, filename = decrypt_file(
                encrypted.getvalue(), aes_key, hmac_key
            )

            st.session_state.recovered = {
                "data": data,
                "filename": filename,
                "time": time.perf_counter() - start
            }

        except Exception as e:
            st.session_state.recovered = None
            st.error(f"Decryption failed: {type(e).__name__}: {e}")

    result = st.session_state.recovered

    if result:
        st.success("File decrypted successfully.")
        st.write(f"Decryption time: {result['time']:.4f} seconds")

        st.download_button(
            "Download recovered file",
            result["data"],
            file_name=result["filename"]
        )
