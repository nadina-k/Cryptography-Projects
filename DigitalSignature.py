# To run this code
# 1. Save the file as DigitalSignature.py
# 2. Open a terminal or command prompt.
# 3. Navigate to the directory containing the file.
# 4. Run the script using the command:
#       python DigitalSignature.py
# Ensure Python 3 is installed on your system.
import math

# Reusing my custom hash from Task 5
def custom_hash(message, output_bits=20):
    """hash function from Task 5"""
    h0 = 0x6A09E667
    h1 = 0xBB67AE85
    byte_array = bytearray(message.encode('utf-8'))
    for byte in byte_array:
        h0 = (h0 + byte) & 0xFFFFFFFF
        h0 = (h0 << 3) | (h0 >> 29)
        h0 ^= h1
        h1 = (h1 + h0) & 0xFFFFFFFF
        h1 = (h1 << 7) | (h1 >> 25)
    return (h0 ^ h1) & ((1 << output_bits) - 1)

# RSA Key Generation 
def generate_rsa_keys():
    """Generate RSA keys """
    p, q = 1013, 1019 # using primes that generated from RSA code in Q4
    n = p * q
    phi = (p-1)*(q-1)
    e = 65537  # Common public exponent
    d = pow(e, -1, phi)  # Modular inverse (private exponent)
    return (n, e), (n, d)

# Digital Signature Functions
def sign_message(message, private_key):
    """Create RSA signature using our custom hash"""
    n, d = private_key
    # Step 1: Create message digest using our custom hash
    message_digest = custom_hash(message)
    # Step 2: Sign the digest (m^d mod n)
    signature = pow(message_digest, d, n)
    return signature

def verify_signature(message, signature, public_key):
    """Verify RSA signature"""
    n, e = public_key
    # Step 1: Decrypt signature (s^e mod n)
    decrypted_hash = pow(signature, e, n)
    # Step 2: Compute message hash
    actual_hash = custom_hash(message)
    # Step 3: Compare
    return decrypted_hash == actual_hash

# Main Demonstration
def main():
    # The financial message from ABSecure
    message = "Transfer $571.99 from ABSecure Acc 12345 to Westpac Acc 135791 BSB 3344."
    

    public_key, private_key = generate_rsa_keys()
    
    print("ABSecure Digital Signature Demonstration")
    print("="*50)
    print("How to use this demonstration:")
    print("1. The code will automatically generate RSA keys")
    print("2. It will sign a sample financial message")
    print("3. It will verify the signature")
    print("4. It will demonstrate what happens with a tampered message")
    print("="*50)
    print("\nKey Generation:")
    print(f"Public Key (n, e): {public_key}")
    print(f"Private Key (n, d): {private_key}\n")
    
    print(f"Original Message:\n{message}\n")
    
    # Signing process
    signature = sign_message(message, private_key)
    print(f"Signature: {signature}\n")
    
    # Verification process (receiving bank)
    is_valid = verify_signature(message, signature, public_key)
    print(f"Signature Verification Result: {'VALID' if is_valid else 'INVALID'}")
    
    # Tampered message test
    tampered_msg = message.replace("571.99", "9999.99")
    print("\n------Testing with tampered message------")
    print(f"Tampered Message= {tampered_msg}")
    is_valid_tampered = verify_signature(tampered_msg, signature, public_key)
    print(f"Tampered Message Verification Result: {'VALID' if is_valid_tampered else 'INVALID'} ")

if __name__ == "__main__":
    print("Running ABSecure Digital Signature Demonstration...\n")
    main()