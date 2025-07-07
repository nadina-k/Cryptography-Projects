import random
def is_prime(n):
    """Check if a number is prime using the Miller-Rabin primality test.(n.d. geeks for geeks)"""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n as 2^r * d + 1
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(5):  # 5 rounds of testing
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_large_prime(min_val=100, max_val=10000):
    """Generate a random prime number between min_val and max_val."""
    while True:
        p = random.randint(min_val, max_val)
        if is_prime(p):
            return p

def gcd(a, b):
    """Calculate the greatest common divisor of a and b."""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """Calculate the modular multiplicative inverse of e modulo phi."""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            gcd, x, y = extended_gcd(b % a, a)
            return gcd, y - (b // a) * x, x
    
    g, x, y = extended_gcd(e, phi)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % phi

def generate_key_pair(p=None, q=None):
    """Generate RSA key pair."""
    if p is None:
        p = generate_large_prime()
    if q is None:
        q = generate_large_prime()
        # Make sure p and q are different
        while p == q:
            q = generate_large_prime()
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choose e such that 1 < e < phi and gcd(e, phi) = 1
    e = 65537  #  value for public key e
    
    # If e and phi are not coprime, choose another e
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    
    # Compute d, the modular multiplicative inverse of e (mod phi)
    d = mod_inverse(e, phi)
    
    # Public key is (n, e), private key is (n, d)
    return (p, q, n, e, d)

def string_to_int(message):
    """Convert a string to an integer."""
    return int.from_bytes(message.encode('utf-8'), 'big')

def int_to_string(number):
    """Convert an integer to a string."""
    # Calculate number of bytes needed
    num_bytes = (number.bit_length() + 7) // 8
    return number.to_bytes(num_bytes, 'big').decode('utf-8', errors='ignore')

def square_and_multiply(base, exponent, modulus):
    """Efficiently calculate (base^exponent) % modulus using square and multiply algorithm."""
    result = 1
    base = base % modulus
    
    while exponent > 0:
        # If exponent is odd, multiply result with base
        if exponent % 2 == 1:
            result = (result * base) % modulus
        
        # Square the base
        base = (base * base) % modulus
        
        # Divide exponent by 2
        exponent = exponent >> 1
    
    return result

def encrypt(message, public_key):
    """Encrypt a message using RSA public key."""
    n, e = public_key
    # Convert message to integer
    m = string_to_int(message)
    
    # Check if message is too large for RSA
    if m >= n:
        raise ValueError("Message is too large for the given key size")
    
    # Encrypt: c = m^e mod n
    c = square_and_multiply(m, e, n)
    return c

def decrypt(ciphertext, private_key, n):
    """Decrypt a message using RSA private key."""
    d = private_key
    # Decrypt: m = c^d mod n
    m = square_and_multiply(ciphertext, d, n)
    
    # Convert integer back to string
    return int_to_string(m)

def main():
    # Use the ABSecure symmetric key
    symmetric_key = "ABSecureTopSecret123"
    
    print("ABSecure RSA Key Generation and Symmetric Key Exchange")
    print("-" * 60)
    print(f"Symmetric Key (K): {symmetric_key}")
    
    # Generate RSA key pair for ABSecure
    print("\nGenerating RSA key pair with primes between 100 and 10000...")
    p, q, n, e, d = generate_key_pair()
    
    print(f"Prime p: {p}")
    print(f"Prime q: {q}")
    print(f"Modulus n (p*q): {n}")
    print(f"Public exponent e: {e}")
    print(f"Private exponent d: {d}")
    
    # Encrypt the symmetric key using the public key
    public_key = (n, e)
    print("\nEncrypting symmetric key...")
    encrypted_key = encrypt(symmetric_key, public_key)
    print(f"Encrypted Key: {encrypted_key}")
    
    # Decrypt the symmetric key using the private key
    print("\nDecrypting symmetric key...")
    decrypted_key = decrypt(encrypted_key, d, n)
    print(f"Decrypted Key: {decrypted_key}")
    
    # Verify the decryption is correct
    if decrypted_key == symmetric_key:
        print("\nSuccess! The decrypted key matches the original symmetric key.")
    else:
        print("\nError: The decrypted key doesn't match the original symmetric key.")

if __name__ == "__main__":
    main()