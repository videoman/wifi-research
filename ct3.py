#!/usr/bin/env python3
"""
CT3 NTLM Hash Key Recovery Tool

This script recovers the encryption key from CT3 hash values used in NTLM authentication.
It supports both standard recovery and recovery with ESS values.
"""
import hashlib
import argparse


def permute(x, table, in_bits):
    """
    Permute bits of integer x according to a given table (1-indexed bit positions).
    
    Args:
        x: Input integer to permute bits from
        table: List of 1-indexed bit positions to select
        in_bits: Number of bits in the input integer
        
    Returns:
        Integer with bits permuted according to the table
    """
    out = 0
    for pos in table:
        bit = (x >> (in_bits - pos)) & 1  # extract bit at position 'pos'
        out = (out << 1) | bit
    return out


def des_encrypt(block64, key64, des_tables):
    """
    DES encrypt a 64-bit block with a 64-bit key.
    
    Args:
        block64: 64-bit integer to encrypt
        key64: 64-bit integer key
        des_tables: Dictionary containing DES tables (PC1, PC2, IP, FP, E, P, S_boxes)
        
    Returns:
        64-bit integer result of the encryption
    """
    # Extract tables from des_tables
    PC1 = des_tables['PC1']
    PC2 = des_tables['PC2']
    IP = des_tables['IP']
    FP = des_tables['FP']
    E = des_tables['E']
    P = des_tables['P']
    S_boxes = des_tables['S_boxes']
    
    # 1. Generate 16 subkeys from key64
    key56 = permute(key64, PC1, 64)          # apply PC1 to get 56-bit key
    C = key56 >> 28                          # left half
    D = key56 & ((1 << 28) - 1)              # right half
    subkeys = []
    
    # left-rotation schedule for each round (NTLMv1 uses standard DES rotations)
    rotations = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    for r in rotations:
        # Left circular shift
        C = ((C << r) & ((1 << 28) - 1)) | (C >> (28 - r))
        D = ((D << r) & ((1 << 28) - 1)) | (D >> (28 - r))
        CD = (C << 28) | D
        subkeys.append(permute(CD, PC2, 56))
    
    # 2. Initial Permutation of block
    permuted = permute(block64, IP, 64)
    L = permuted >> 32
    R = permuted & 0xFFFFFFFF
    
    # 3. 16 Feistel rounds
    for i in range(16):
        # Expand R to 48 bits and XOR with subkey
        ER = permute(R, E, 32)
        xor_out = ER ^ subkeys[i]
        
        # S-box substitutions (48-bit to 32-bit)
        S_output = 0
        for box_index in range(8):
            six_bits = (xor_out >> (42 - 6*box_index)) & 0x3F  # extract 6 bits
            row = ((six_bits >> 5) << 1) | (six_bits & 1)      # b5 and b0
            col = (six_bits >> 1) & 0xF                        # b4..b1
            S_val = S_boxes[box_index][row][col]
            S_output = (S_output << 4) | S_val
        
        # P permutation on 32-bit S-box output
        f_out = permute(S_output, P, 32)
        
        # Feistel swap
        newL = R
        newR = L ^ f_out
        L, R = newL, newR
    
    # 4. Final swap and permutation (FP)
    combined = (R << 32) | L  # Note: swap L and R before final perm
    return permute(combined, FP, 64)


def get_des_tables():
    """
    Returns a dictionary containing all DES tables needed for the algorithm.
    
    Returns:
        Dictionary with PC1, PC2, IP, FP, E, P, and S_boxes tables
    """
    # DES constants (tables)
    PC1 = [  # 64-bit key to 56-bit (drop parity bits)
        57, 49, 41, 33, 25, 17,  9,
         1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
         7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 28, 20, 12,  4
    ]
    
    PC2 = [  # 56-bit key to 48-bit subkey
        14, 17, 11, 24,  1,  5,
         3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8,
        16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]
    
    IP = [  # Initial Permutation on 64-bit data
        58, 50, 42, 34, 26, 18, 10,  2,
        60, 52, 44, 36, 28, 20, 12,  4,
        62, 54, 46, 38, 30, 22, 14,  6,
        64, 56, 48, 40, 32, 24, 16,  8,
        57, 49, 41, 33, 25, 17,  9,  1,
        59, 51, 43, 35, 27, 19, 11,  3,
        61, 53, 45, 37, 29, 21, 13,  5,
        63, 55, 47, 39, 31, 23, 15,  7
    ]
    
    FP = [  # Final Permutation (inverse of IP)
        40,  8, 48, 16, 56, 24, 64, 32,
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25
    ]
    
    # Expansion table (32-bit to 48-bit)
    E = [
        32,  1,  2,  3,  4,  5,
         4,  5,  6,  7,  8,  9,
         8,  9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32,  1
    ]
    
    # S-boxes (8 boxes, each 4x16)
    S_boxes = [
        # S1
        [
            [14, 4, 13, 1,  2, 15, 11, 8,  3, 10,  6, 12,  5, 9, 0, 7],
            [ 0, 15,  7, 4, 14,  2, 13, 1, 10,  6, 12, 11,  9, 5, 3, 8],
            [ 4, 1, 14, 8, 13,  6,  2, 11, 15, 12,  9,  7,  3,10, 5, 0],
            [15,12,  8, 2,  4,  9,  1, 7,  5, 11,  3, 14, 10, 0, 6,13]
        ],
        # S2
        [
            [15, 1, 8, 14,  6,11, 3, 4,  9, 7, 2,13, 12, 0, 5,10],
            [ 3,13, 4, 7, 15, 2, 8,14, 12, 0, 1,10,  6, 9,11, 5],
            [ 0,14, 7,11, 10, 4,13, 1,  5, 8,12, 6,  9, 3, 2,15],
            [13, 8,10, 1,  3,15, 4, 2, 11, 6, 7,12,  0, 5,14, 9]
        ],
        # S3
        [
            [10, 0, 9,14,  6, 3,15, 5, 1,13,12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9,  3, 4, 6,10, 2, 8, 5,14, 12,11,15, 1],
            [13, 6, 4, 9,  8,15, 3, 0,11, 1, 2,12,  5,10,14, 7],
            [ 1,10,13, 0,  6, 9, 8, 7, 4,15, 14, 3, 11, 5, 2,12]
        ],
        # S4
        [
            [7,13,14, 3,  0, 6, 9,10, 1, 2, 8, 5, 11,12, 4,15],
            [13, 8,11, 5,  6,15, 0, 3, 4, 7, 2,12,  1,10,14, 9],
            [10, 6, 9, 0, 12,11, 7,13,15, 1, 3,14,  5, 2, 8, 4],
            [ 3,15, 0, 6, 10, 1,13, 8, 9, 4, 5,11, 12, 7, 2,14]
        ],
        # S5
        [
            [ 2,12, 4, 1,  7,10,11, 6,  8, 5, 3,15, 13, 0,14, 9],
            [14,11, 2,12,  4, 7,13, 1,  5, 0,15,10,  3, 9, 8, 6],
            [ 4, 2, 1,11, 10,13, 7, 8, 15, 9,12, 5,  6, 3, 0,14],
            [11, 8,12, 7,  1,14, 2,13,  6,15, 0, 9, 10, 4, 5, 3]
        ],
        # S6
        [
            [12, 1,10,15,  9, 2, 6, 8,  0,13, 3, 4, 14, 7, 5,11],
            [10,15, 4, 2,  7,12, 9, 5,  6, 1,13,14,  0,11, 3, 8],
            [ 9,14,15, 5,  2, 8,12, 3,  7, 0, 4,10,  1,13,11, 6],
            [ 4, 3, 2,12,  9, 5,15,10, 11,14, 1, 7,  6, 0, 8,13]
        ],
        # S7
        [
            [ 4,11, 2,14, 15, 0, 8,13,  3,12, 9, 7,  5,10, 6, 1],
            [13, 0,11, 7,  4, 9, 1,10, 14, 3, 5,12,  2,15, 8, 6],
            [ 1, 4,11,13, 12, 3, 7,14, 10,15, 6, 8,  0, 5, 9, 2],
            [ 6,11,13, 8,  1, 4,10, 7,  9, 5, 0,15, 14, 2, 3,12]
        ],
        # S8
        [
            [13, 2, 8, 4,  6,15,11, 1, 10, 9, 3,14,  5, 0,12, 7],
            [ 1,15,13, 8, 10, 3, 7, 4, 12, 5, 6,11,  0,14, 9, 2],
            [ 7,11, 4, 1,  9,12,14, 2,  0, 6,10,13, 15, 3, 5, 8],
            [ 2, 1,14, 7,  4,10, 8,13, 15,12, 9, 0,  3, 5, 6,11]
        ]
    ]
    
    # P permutation (32-bit output after S-boxes)
    P = [
        16,  7, 20, 21,
        29, 12, 28, 17,
         1, 15, 23, 26,
         5, 18, 31, 10,
         2,  8, 24, 14,
        32, 27,  3,  9,
        19, 13, 30,  6,
        22, 11,  4, 25
    ]
    
    return {
        'PC1': PC1,
        'PC2': PC2,
        'IP': IP,
        'FP': FP,
        'E': E,
        'S_boxes': S_boxes,
        'P': P
    }


def construct_des_key(nthash_bytes):
    """
    Construct an 8-byte DES key from a 7-byte input by adding parity bits.
    
    Args:
        nthash_bytes: 7-byte list to construct key from
        
    Returns:
        Bytes object representing the 8-byte DES key
    """
    # Transform 7-byte block into 8-byte DES key with parity bits
    k0 = nthash_bytes[0]
    k1 = ((nthash_bytes[0] << 7) | (nthash_bytes[1] >> 1)) & 0xFF
    k2 = ((nthash_bytes[1] << 6) | (nthash_bytes[2] >> 2)) & 0xFF
    k3 = ((nthash_bytes[2] << 5) | (nthash_bytes[3] >> 3)) & 0xFF
    k4 = ((nthash_bytes[3] << 4) | (nthash_bytes[4] >> 4)) & 0xFF
    k5 = ((nthash_bytes[4] << 3) | (nthash_bytes[5] >> 5)) & 0xFF
    k6 = ((nthash_bytes[5] << 2) | (nthash_bytes[6] >> 6)) & 0xFF
    k7 = ((nthash_bytes[6] << 1)) & 0xFF
    
    # Set LSB of each byte to 1 (parity bits)
    key_bytes = bytes([k0|1, k1|1, k2|1, k3|1, k4|1, k5|1, k6|1, k7|1])
    return key_bytes


def recover_key_from_ct3(ct3_hex, salt_hex, ess_hex=None, verbose=False):
    """
    Recover the encryption key from CT3 hash and salt values.
    
    Args:
        ct3_hex: CT3 hash value as a hex string (16 characters/8 bytes)
        salt_hex: Salt value as a hex string (16 characters/8 bytes)
        ess_hex: Optional ESS value as a hex string (48 characters/24 bytes)
        verbose: Whether to print verbose output
        
    Returns:
        Recovered key as a hex string (4 characters/2 bytes) or None if not found
    """
    # Get DES tables
    des_tables = get_des_tables()
    
    # Convert inputs from hex strings to integers (64-bit for ct3 and salt)
    ct3_bytes = bytes.fromhex(ct3_hex)
    salt_bytes = bytes.fromhex(salt_hex)
    if len(ct3_bytes) != 8 or len(salt_bytes) != 8:
        raise ValueError("ct3 and salt must be 8 bytes (16 hex chars) each")
    
    ct3_val = int.from_bytes(ct3_bytes, 'big')
    salt_val = int.from_bytes(salt_bytes, 'big')

    # If ESS provided and last 16 bytes are all 0, use MD5(salt + first 8 bytes of ESS) as new salt
    if ess_hex:
        ess_bytes = bytes.fromhex(ess_hex)
        if len(ess_bytes) != 24:
            raise ValueError("ESS must be 24 bytes (48 hex chars)")
        
        if ess_bytes[8:] == b'\x00' * 16:  # check if last 16 bytes are zero
            md5_input = salt_bytes + ess_bytes[:8]
            digest = hashlib.md5(md5_input).digest()
            salt_val = int.from_bytes(digest[:8], 'big')  # use first 8 bytes of MD5 as salt
            
            if verbose:
                print("Using modified salt (MD5 of salt + first 8 bytes of ESS)")
                print(f"Modified salt: {digest[:8].hex()}")

    # Brute-force search for the 16-bit key
    found_key = None
    attempts = 0
    
    if verbose:
        print("Starting brute force key search...")
    
    for i in range(0x10000):  # 0 to 65535
        attempts += 1
        
        # Construct 7-byte block (nthash) from candidate i (2 bytes) + 5 zero bytes
        nthash_bytes = [i & 0xFF, (i >> 8) & 0xFF, 0, 0, 0, 0, 0]
        
        # Get DES key from nthash bytes
        key_bytes = construct_des_key(nthash_bytes)
        key_val = int.from_bytes(key_bytes, 'big')
        
        # DES encrypt the salt with this key and compare to ct3
        if des_encrypt(salt_val, key_val, des_tables) == ct3_val:
            found_key = i
            break
        
        # Status update for long operations
        if verbose and i % 10000 == 0 and i > 0:
            print(f"Tried {i:,} keys ({i/0x10000:.1%} complete)")
    
    if found_key is None:
        if verbose:
            print(f"No key found after trying {attempts:,} possibilities")
        return None

    # Format the found 16-bit value as a hex string (low-order byte first, as in C output)
    low = found_key & 0xFF
    high = (found_key >> 8) & 0xFF
    result = f"{low:02x}{high:02x}"
    
    if verbose:
        print(f"Found key after {attempts:,} attempts")
    
    return result


def main():
    """Main function for command-line usage."""
    parser = argparse.ArgumentParser(
        description='CT3 NTLM Hash Key Recovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python ct3.py -c C4A70D3BEBD70233 -s 1122334455667788
  python ct3.py -c 7D01513435B36DCA -s 1122334455667788 -e 1FA1B9C4ED8E570200000000000000000000000000000000
  python ct3.py --ct3 C4A70D3BEBD70233 --salt 1122334455667788 --verbose
        '''
    )
    
    parser.add_argument('-c', '--ct3', required=True, help='CT3 hash value (16 hex characters)')
    parser.add_argument('-s', '--salt', required=True, help='Salt value (16 hex characters)')
    parser.add_argument('-e', '--ess', help='ESS value (48 hex characters, optional)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Validate input lengths
    if len(args.ct3) != 16:
        parser.error("CT3 hash must be 16 hex characters (8 bytes)")
    if len(args.salt) != 16:
        parser.error("Salt must be 16 hex characters (8 bytes)")
    if args.ess and len(args.ess) != 48:
        parser.error("ESS must be 48 hex characters (24 bytes)")
    
    # Validate hex characters
    try:
        bytes.fromhex(args.ct3)
        bytes.fromhex(args.salt)
        if args.ess:
            bytes.fromhex(args.ess)
    except ValueError:
        parser.error("All inputs must be valid hexadecimal")
    
    if args.verbose:
        print(f"CT3: {args.ct3}")
        print(f"Salt: {args.salt}")
        if args.ess:
            print(f"ESS: {args.ess}")
        print("Starting key recovery...")
    
    # Run the key recovery
    key = recover_key_from_ct3(args.ct3, args.salt, args.ess, args.verbose)
    
    if key:
        print(f"Recovered key: {key}")
    else:
        print("No key found. Check your inputs.")


if __name__ == "__main__":
    main()
