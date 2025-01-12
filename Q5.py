import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from scapy.all import IP, TCP, UDP, rdpcap, Ether
import hashlib
from Crypto.Hash import HMAC, SHA256

def encrypt_data(data, key, iv):
    """
    Initialize an AES cipher object using CBC mode and encrypt data.

    :param data: The plaintext data to be encrypted (byte string).
    :param key: The encryption key (byte string).
    :param iv: The initialization vector (byte string).
    :return: Encrypted data (byte string).
    """
    # Initialize the AES cipher for CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Encrypt the data after padding it to ensure it fits the block size
    return cipher.encrypt(pad(data, AES.block_size))

def compute_hmac(data, key):
    """
    Compute HMAC for the given data using SHA-256.

    :param data: Data to be authenticated (byte string).
    :param key: HMAC key (byte string).
    :return: HMAC value (byte string).
    """
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(data)
    return hmac.digest()

def calculate_packet_hash(packet):
    """
    Calculate a SHA-256 hash of the given packet for integrity checking.

    :param packet: The Scapy packet object.
    :return: SHA-256 hash as a hexadecimal string.
    """
    hash_obj = hashlib.sha256()
    hash_obj.update(bytes(packet))
    return hash_obj.hexdigest()

def calculate_padding_length(data_length):
    padding_length = AES.block_size - ((data_length) % AES.block_size)
    if padding_length == 0:
        padding_length = AES.block_size
    return padding_length

def make_esp_payload(data_to_encrypt, next_header, key, iv, hmac_key):
    padding_length = calculate_padding_length(len(data_to_encrypt))

    plaintext_data = data_to_encrypt + bytes([padding_length] * padding_length) + bytes([padding_length]) + bytes([next_header])

    encrypted_data = encrypt_data(plaintext_data, key, iv)

    # ESP Header
    spi = bytes([1]) * 4            
    seq_num = b'\x00\x00\x00\x01' 
    esp_header = spi + seq_num + iv

    # ESP Header and Encrypted Data
    esp_payload = esp_header + encrypted_data

    # HMAC over ESP Header and Encrypted Data
    hmac_value = compute_hmac(esp_payload, hmac_key)

    # Final payload
    final_payload = esp_payload + hmac_value

    return final_payload

def main():
    """
    Main function to process command line arguments, read pcap file, encrypt payload,
    construct ESP packet, and display results.
    """
    try:
        if len(sys.argv) != 3:
            raise ValueError("Usage: python3 Q5.py [path_to_pcap_file] [mode]")
        
        packet_file = sys.argv[1]
        mode = sys.argv[2].strip().lower()

        try:
            packets = rdpcap(packet_file)
        except Exception as e:
            raise ValueError("Failed to read the pcap file.")
        
        if mode not in ["transport", "tunnel"]:
            raise ValueError("Invalid mode. Choose 'tunnel' or 'transport'.")
        
        original_packet = packets[0]
        
         # Remove Ethernet layer if present
        if Ether in original_packet:
            original_packet = original_packet[IP]

        key = hashlib.sha256(b"secret_key").digest()[:16]  # AES Key
        iv = hashlib.sha256(b"initialization_vector").digest()[:16]  # AES IV
        hmac_key = hashlib.sha256(b"hmac_key").digest()  # HMAC Key

        if mode == "transport":
            if TCP in original_packet:
                payload = bytes(original_packet[TCP]) 
                next_header = 6   
            elif UDP in original_packet:
                payload = bytes(original_packet[UDP])  
                next_header = 17 

            final_payload = make_esp_payload(payload, next_header, key, iv, hmac_key)

            original_packet.remove_payload()
            original_packet.add_payload(final_payload)

            packet_hash = calculate_packet_hash(original_packet)
            print(packet_hash)

        elif mode == "tunnel": 
            if TCP in original_packet:
                next_header = 6
            elif UDP in original_packet:
                next_header = 17

            final_payload = make_esp_payload(bytes(original_packet), next_header, key, iv, hmac_key)

            new_ip_header = IP(dst=original_packet.dst, src='192.168.99.99')

            new_ip_header.add_payload(final_payload)

            packet_hash = calculate_packet_hash(new_ip_header)
            print(packet_hash)
        
    except ValueError as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
