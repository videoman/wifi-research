import re
import binascii
from Crypto.Cipher import DES

def parse_hostapd_wpe_output(file_path):
    """
    Extracts the MS-CHAPv2 challenge and response from hostapd-wpe output file.
    """
    with open(file_path, "r") as file:
        content = file.read()

    # Regex patterns to extract challenge and response
    challenge_match = re.search(r"challenge:\s*([0-9a-fA-F]+)", content)

    response_match = re.search(r"response:\s*([0-9a-fA-F]+)", content)

    if not challenge_match or not response_match:
        raise ValueError("Failed to extract MS-CHAPv2 challenge/response from file.")

    challenge = binascii.unhexlify(challenge_match.group(1))
#    if ':' in challenge:
#        challenge = challenge.replace(':', '')

    response = binascii.unhexlify(response_match.group(1))
#    if ':' in response:
#        response = response.replace(':', '')

    return challenge, response

def des_encrypt_block(key7, challenge):
    """
    Encrypts the challenge using a 7-byte key (converted to 8-byte DES key).
    """
    key8 = convert_7byte_to_8byte(key7)
    cipher = DES.new(key8, DES.MODE_ECB)
    return cipher.encrypt(challenge)

def convert_7byte_to_8byte(key7):
    """
    Converts a 7-byte key into an 8-byte DES key by adding parity bits.
    """
    key8 = []
    for i in range(7):
        key8.append(key7[i])
    key8.append(0)  # Append a parity bit
    return bytes(key8)

def derive_des_keys(nt_hash):
    """
    Splits the 16-byte NT hash into three 7-byte DES keys.
    """
    key1 = nt_hash[:7]
    key2 = nt_hash[7:14]
    key3 = nt_hash[14:] + b'\x00' * (7 - len(nt_hash[14:]))  # Pad last key if needed
    return key1, key2, key3

def mschapv2_des_encrypt(challenge, nt_hash):
    """
    Derives DES keys from NT hash and encrypts the challenge.
    """
    key1, key2, key3 = derive_des_keys(nt_hash)
    encrypted1 = des_encrypt_block(key1, challenge)
    encrypted2 = des_encrypt_block(key2, challenge)
    encrypted3 = des_encrypt_block(key3, challenge)
    return encrypted1, encrypted2, encrypted3

if __name__ == "__main__":
    # Specify the hostapd-wpe output file
    file_path = "hostapd-wpe.log"

    try:
        # Extract MS-CHAPv2 challenge and response from file
        challenge, response = parse_hostapd_wpe_output(file_path)

        print(f"Extracted Challenge: {binascii.hexlify(challenge).decode()}")
        print(f"Extracted Response: {binascii.hexlify(response).decode()}")

        # Example NT hash (MD4 of password)
        nt_hash = binascii.unhexlify("0123456789abcdef0123456789abcdef")

        # Get the three DES encrypted outputs
        enc1, enc2, enc3 = mschapv2_des_encrypt(challenge, nt_hash)

        # Print results
        print("Encrypted Block 1:", binascii.hexlify(enc1).decode())
        print("Encrypted Block 2:", binascii.hexlify(enc2).decode())
        print("Encrypted Block 3:", binascii.hexlify(enc3).decode())

    except Exception as e:
        print("Error:", str(e))

