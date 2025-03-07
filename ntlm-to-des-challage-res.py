import binascii
from Crypto.Cipher import DES

def adjust_des_key(key):
    """
    Converts a 7-byte key into an 8-byte DES key with proper parity bits.
    
    :param key: 7-byte key as bytes.
    :return: 8-byte DES key with parity bits.
    """
    key_bytes = bytearray(8)
    key_bytes[0] = key[0] & 0xFE
    key_bytes[1] = ((key[0] << 7) | (key[1] >> 1)) & 0xFE
    key_bytes[2] = ((key[1] << 6) | (key[2] >> 2)) & 0xFE
    key_bytes[3] = ((key[2] << 5) | (key[3] >> 3)) & 0xFE
    key_bytes[4] = ((key[3] << 4) | (key[4] >> 4)) & 0xFE
    key_bytes[5] = ((key[4] << 3) | (key[5] >> 5)) & 0xFE
    key_bytes[6] = ((key[5] << 2) | (key[6] >> 6)) & 0xFE
    key_bytes[7] = (key[6] << 1) & 0xFE
    return bytes(key_bytes)

def des_encrypt(plaintext, key):
    """
    Encrypts an 8-byte plaintext using DES in ECB mode.
    
    :param plaintext: 8-byte challenge as bytes.
    :param key: 8-byte DES key as bytes.
    :return: Encrypted 8-byte response.
    """
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(plaintext)

def mschapv2_response(nt_hash_hex, challenge_hex):
    """
    Encrypts an MSCHAPv2 response using an NT hash and a challenge.
    
    :param nt_hash_hex: 32-character NT hash in hex format (16 bytes).
    :param challenge_hex: 16-character challenge in hex format (8 bytes).
    :return: The 24-byte MSCHAPv2 response as a hex string.
    """
    nt_hash = bytes.fromhex(nt_hash_hex)
    challenge = bytes.fromhex(challenge_hex)

    if len(nt_hash) != 16 or len(challenge) != 8:
        raise ValueError("NT hash must be 16 bytes, challenge must be 8 bytes.")

    # Split NT hash into three 7-byte chunks, padding the last one
    keys = [
        nt_hash[:7],             # First 7 bytes
        nt_hash[7:14],           # Next 7 bytes
        nt_hash[14:] + b'\x00' * (7 - len(nt_hash[14:]))  # Last 2 bytes + padding
    ]

    # Convert 7-byte keys into 8-byte DES keys (adding parity bits)
    des_keys = [adjust_des_key(k) for k in keys]

    # Encrypt the challenge with each key
    encrypted_blocks = [des_encrypt(challenge, k) for k in des_keys]

    # Concatenate the results (24 bytes total)
    response = b''.join(encrypted_blocks)

    return response.hex()

# Example usage
if __name__ == "__main__":
    #nt_hash = "58a478135a93ac3bf058a5ea0e8fdb71"  # NT Hash of 'Password123'
    nt_hash = "0cb6948805f797bf2a82807973b89537"  # NT Hash of 'test'
    challenge = "169e5b8f18dd92ca"  # Example challenge (8 bytes)

    response = mschapv2_response(nt_hash, challenge)
    print(f"MSCHAPv2 Encrypted Response: {response}")

