import re
import binascii

def parse_hostapd_wpe_log(file_path):
    """
    Parses the hostapd-wpe log file to extract MS-CHAPv2 credentials.
    """
    with open(file_path, "r") as file:
        content = file.read()

    # Extract username
    username_match = re.search(r"username:\s*([^\n\r]+)", content)
    username = username_match.group(1).strip() if username_match else "unknown"

    # Extract challenge (convert colon-separated hex to standard hex)
    challenge_match = re.search(r"challenge:\s*([0-9a-fA-F:]+)", content)
    challenge = challenge_match.group(1).replace(":", "").strip() if challenge_match else None

    # Extract response (convert colon-separated hex to standard hex)
    response_match = re.search(r"response:\s*([0-9a-fA-F:]+)", content)
    response = response_match.group(1).replace(":", "").strip() if response_match else None

    if not challenge or not response or len(response) != 48:
        raise ValueError("Invalid MS-CHAPv2 challenge/response format.")

    return username, challenge, response

def extract_des_blocks(response):
    """
    Extracts three 8-byte DES encrypted blocks from the 24-byte response.
    """
    enc1 = response[:16]   # First 8-byte block (16 hex chars)
    enc2 = response[16:32] # Second 8-byte block (16 hex chars)
    enc3 = response[32:]   # Third 8-byte block (16 hex chars)
    return enc1, enc2, enc3

if __name__ == "__main__":
    file_path = "hostapd-wpe.log"  # Change this to your log file path

    try:
        # Extract credentials from log
        username, challenge, response = parse_hostapd_wpe_log(file_path)

        print(f"Extracted Username: {username}")
        print(f"Extracted Challenge: {challenge}")
        print(f"Extracted Response: {response}")

        # Extract three encrypted blocks
        enc1, enc2, enc3 = extract_des_blocks(response)

        print("Encrypted Block 1:", enc1)
        print("Encrypted Block 2:", enc2)
        print("Encrypted Block 3:", enc3)

        # Format for Hashcat mode 14000
        hashcat_format = f"$MSCHAPv2${username}*{challenge}*{enc1}*{enc2}*{enc3}"
        
        print("\nHashcat Input Format (mode 14000):")
        print(hashcat_format)

        # Save to file for Hashcat input
        with open("hashcat_mschapv2.txt", "w") as f:
            f.write(hashcat_format + "\n")

        print("\nSaved to hashcat_mschapv2.txt. Use this with hashcat mode 14000.")

    except Exception as e:
        print("Error:", str(e))

