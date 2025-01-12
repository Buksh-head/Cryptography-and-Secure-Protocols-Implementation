from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
import os

def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Derives a cryptographic key from a given password and salt using PBKDF2 HMAC.
    
    Parameters:
    - password (bytes): The password used to generate the key.
    - salt (bytes): A salt used to derive the key. 
    
    Returns:
    - bytes: The derived 256-bit (32 bytes) cryptographic key.
    """
    # Use a default salt if no salt is provided
    if len(salt) == 0:
        salt = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password)
    return key


def add_padding(plaintext: bytes, block_size: int) -> bytes:
    """
    Adds padding to the plaintext to make its length a multiple of the block size.
    Padding should follow PKCS#7 padding scheme. This scheme adds padding bytes where each byte's value is equal to the number of padding bytes added. For example, if 3 bytes of padding are needed, the padding would be 03 03 03.
    
    Parameters:
    - plaintext (bytes): The data to be encrypted.
    - block_size (int): The block size required by the encryption algorithm.
    
    Returns:
    - bytes: The padded plaintext.
    """
    padding_length = block_size - (len(plaintext) % block_size)
    padding = bytes([padding_length] * padding_length)
    return plaintext + padding

def remove_padding(padded_plaintext: bytes) -> bytes:
    """
    Removes padding from the decrypted plaintext.
    
    Parameters:
    - padded_plaintext (bytes): The decrypted data with padding.
    
    Returns:
    - bytes: The plaintext without padding.
    """
    padding_length = padded_plaintext[-1]
    return padded_plaintext[:-padding_length]

def encrypt_aes(mode: str, key: bytes, plaintext: bytes, iv: bytes) -> tuple:
    """
    Encrypts the plaintext using AES in the specified mode with the given key and IV.
    
    Parameters:
    - mode (str): The AES encryption mode (e.g., ECB, CBC, CFB, OFB, CTR, GCM).
    - key (bytes): The encryption key.
    - plaintext (bytes): The data to encrypt.
    - iv (bytes): The initialization vector (IV) for certain AES modes.
    
    Returns:
    - Tuple (encrypted_data, tag): The encrypted data and the authentication tag (for GCM mode). Set the tag to None if not in GCM mode.
    """
    # Use a default IV if none is provided
    if len(iv) == 0:
        iv = bytes.fromhex("5e8f16368792149f036e937dccd7c95b")

    if mode == "ECB":
        cipher = Cipher(algorithms.AES(key), modes.ECB())
    elif mode == "CBC":
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    elif mode == "CFB":
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    elif mode == "OFB":
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    elif mode == "CTR":
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    elif mode == "GCM":
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    else:
        raise ValueError("Unsupported mode.")
    
    encryptor = cipher.encryptor()
    

    if mode == "ECB" or mode == "CBC":
        padded_plaintext = add_padding(plaintext, algorithms.AES.block_size // 8)
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    elif mode == "GCM":
        padded_plaintext = add_padding(plaintext, algorithms.AES.block_size // 8)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    else:
        padded_plaintext = add_padding(plaintext, algorithms.AES.block_size // 8)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    tag = encryptor.tag if mode == "GCM" else None
    return (ciphertext, tag)


def decrypt_aes(mode: str, key: bytes, ciphertext: bytes, iv: bytes, tag: bytes = None) -> bytes:
    """
    Decrypts the ciphertext using AES in the specified mode with the given key, IV, and tag (if GCM mode).
    
    Parameters:
    - mode (str): The AES decryption mode (e.g., ECB, CBC, CFB, OFB, CTR, GCM).
    - key (bytes): The decryption key.
    - ciphertext (bytes): The encrypted data to decrypt.
    - iv (bytes): The initialization vector (IV).
    - tag (bytes): The authentication tag (for GCM mode).
    
    Returns:
    - bytes: The decrypted plaintext.
    """
    # Use a default IV if none is provided
    if len(iv) == 0:
        iv = bytes.fromhex("5e8f16368792149f036e937dccd7c95b")

    if mode == "ECB":
        cipher = Cipher(algorithms.AES(key), modes.ECB())
    elif mode == "CBC":
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    elif mode == "CFB":
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    elif mode == "OFB":
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    elif mode == "CTR":
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    elif mode == "GCM":
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    else:
        raise ValueError("Unsupported mode.")

    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    if mode == "ECB" or mode == "CBC":
        decrypted_data = remove_padding(decrypted_data)
        
    return decrypted_data

def main():
    """
    Main function to execute the encryption and decryption routine.
    
    This function handles user inputs, including password, salt, IV, and AES mode.
    It performs encryption and decryption, then displays the results.
    """
    try:
        # User input for password (used to derive the key)
        password = input("Enter password: ").encode()
        if len(password) == 0:
            raise ValueError("Password cannot be empty.")

        # User input for salt and IV
        try:
            salt = bytes.fromhex(input("Enter salt (leave blank for default): "))
            iv = bytes.fromhex(input("Enter IV (leave blank for default): "))
        except ValueError:
            raise ValueError("Invalid hex string.")

        # User input for plaintext (data to be encrypted)
        plaintext = input("Enter plaintext: ").encode()
        if len(plaintext) == 0:
            raise ValueError("Plaintext cannot be empty.")

        # User input for AES mode (must be a valid AES mode)
        mode = input("Enter AES mode (ECB, CBC, CFB, OFB, CTR, GCM): ")

        # Deriving the encryption key from the password and salt
        key = derive_key(password, salt)

        # Perform encryption (returns encrypted data and tag for GCM mode)
        encrypted, tag = encrypt_aes(mode, key, plaintext, iv)
        encrypted_b64 = b64encode(encrypted).decode()  # Base64 encode the ciphertext for display
        print(f"Encrypted: {encrypted_b64}")

        # Perform decryption (decrypt the Base64 encoded ciphertext)
        decrypted = decrypt_aes(mode, key, b64decode(encrypted_b64), iv, tag)
        print(f"Decrypted: {decrypted.decode()}")

    except ValueError as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
