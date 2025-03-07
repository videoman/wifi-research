from Crypto.Hash import MD4

def ntlm_hash(password: str) -> str:
    """
    Generates an NTLM hash of a given password using the MD4 algorithm.
    
    :param password: The plaintext password to hash.
    :return: NTLM hash as a 32-character hexadecimal string.
    """
    password_bytes = password.encode('utf-16le')  # Encode password in UTF-16LE
    md4_hash = MD4.new(password_bytes).hexdigest()  # Compute MD4 hash
    return md4_hash

# Example usage
if __name__ == "__main__":
    password = "test"  # Change this to test different passwords
    ntlm = ntlm_hash(password)
    print(f"NTLM Hash of '{password}': {ntlm}")

