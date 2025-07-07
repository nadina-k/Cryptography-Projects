# To run this code:
# 1. Save the code in a file, hash.py.
# 2. Open terminal or command prompt.
# 3. Navigate to the directory containing the file.
# 4. Run the script using the command:
#       python hash.py
# Make sure Python 3 is installed on your system.
def custom_hash(message, output_bits=20):
    """
    Custom hash function for ABSecure message digests
    Input: message string, output_bits
    Output: hexadecimal digest of specified length
    """
    if output_bits < 20:
        raise ValueError("Output must be at least 20 bits")
    
    # Initialize variables with prime numbers
    h0 = 0x6A09E667  # Fractional parts of square roots of first 8 primes
    h1 = 0xBB67AE85
    h2 = 0x3C6EF372
    
    # Convert message to byte array
    byte_array = bytearray(message.encode('utf-8'))
    
    # Process each byte in the message
    for byte in byte_array:
        # Bitwise operations for mixing
        h0 = (h0 + byte) & 0xFFFFFFFF
        h0 = (h0 << 3) | (h0 >> 29)  # Rotate left 3 bits
        h0 ^= h1
        h1 = (h1 + h0) & 0xFFFFFFFF
        h1 = (h1 << 7) | (h1 >> 25)  # Rotate left 7 bits
        h1 ^= h2
        h2 = (h2 + h1) & 0xFFFFFFFF
        h2 = (h2 << 11) | (h2 >> 21)  # Rotate left 11 bits
    
    # Combine the hash values
    combined = (h0 ^ h1 ^ h2) & 0xFFFFFFFF
    
    # Truncate to desired bit length
    mask = (1 << output_bits) - 1
    truncated_hash = combined & mask
    
    # Convert to hexadecimal
    hex_digits = (output_bits + 3) // 4  # Calculate required hex digits
    return f"{truncated_hash:0{hex_digits}x}"

# Main demonstration of the custom hash function
message = "Transfer $571.99 from ABSecure Acc 12345 to Westpac Acc 135791 BSB 3344."
digest = custom_hash(message)
print(f"Message: {message}")
print(f"Digest ({len(digest)*4} bits): {digest}")

# Demonstrate different inputs
test_messages = [
    message,
    message[:-1] + "5",  # Change last digit
    "Transfer $571.99 from ABSecure Acc 12345 to Westpac Acc 135791 BSB 3344",  # Remove period
    "A completely different message"
]

print("\nHash sensitivity demonstration:")
for msg in test_messages:
    print(f"{msg[:100]} → {custom_hash(msg)}")