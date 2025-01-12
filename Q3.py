import random
import sys

def check_prime(num):
    """
    Checks if a number is prime.
    
    Parameters:
    - num (int): The number to check for primality.
    
    Raises:
    - ValueError: If num is not a prime number.
    """
    if num <= 1:
        raise ValueError("Both p and q need to be prime numbers.")
    if num == 2 or num == 3:
        return True
    if num % 2 == 0 or num % 3 == 0:
        raise ValueError("Both p and q need to be prime numbers.")
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            raise ValueError("Both p and q need to be prime numbers.")
        i += 6
    return True

def gcd(a, b):
    """
    Compute the greatest common divisor using Euclid's algorithm.
    
    Parameters:
    - a (int): First integer
    - b (int): Second integer
    
    Returns:
    - int: The greatest common divisor of a and b.
    """
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """
    Compute the modular inverse of e modulo phi using the Extended Euclidean Algorithm.
    
    Parameters:
    - e (int): The exponent to find the inverse of.
    - phi (int): The modulus.
    
    Returns:
    - int: The modular inverse of e modulo phi.
    """
    old_r, r = e, phi
    old_s, s = 1, 0
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    # At this point, old_s is the modular inverse if old_r is 1 (gcd(e, phi) = 1)
    if old_r == 1:
        return old_s % phi
    else:
        raise ValueError("Modular inverse does not exist.")

def generate_keypair(p, q):
    """
    Generate a public and private keypair using two prime numbers.
    Select the smallest possible e that is coprime with phi.
    
    Parameters:
    - p (int): A prime number.
    - q (int): Another prime number.
    
    Returns:
    - tuple: Tuple containing the public and private keys. e.g. ((e, n), (d, n))
    """
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 2
    while gcd(e, phi) != 1:
        e += 1

    d = mod_inverse(e, phi)

    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    """
    Encrypt a plaintext string using a public key.
    
    Parameters:
    - pk (tuple): The public key.
    - plaintext (str): The text to encrypt.
    
    Returns:
    - list: A list of integers representing the encrypted message.
    """
    key, n = pk
    cipher = [pow(ord(char), key, n) for char in plaintext]
    return cipher

def decrypt(pk, ciphertext):
    """
    Decrypt a list of integers back into a string using a private key.
    
    Parameters:
    - pk (tuple): The private key.
    - ciphertext (list): The encrypted message as a list of integers.
    
    Returns:
    - str: The decrypted message.
    """
    key, n = pk
    plaintext = [chr(pow(char, key, n)) for char in ciphertext]
    return ''.join(plaintext)

def main():
    """
    Main function to execute RSA-like encryption and decryption based on command line inputs.
    """
    try:
        if len(sys.argv) != 4:
            raise ValueError("Usage: python Q3.py <prime_p> <prime_q> <message>")

        p = sys.argv[1]
        q = sys.argv[2]
        message = sys.argv[3]

        if len(p.strip()) == 0:
            raise ValueError("Empty value is not allowed.")
        
        if len(q.strip()) == 0:
            raise ValueError("Empty value is not allowed.")
        
        if len(message) == 0:
            raise ValueError("Empty message is not allowed.")
        

        if not p.isdigit():
            raise ValueError("Only integer values are allowed.")
        p = int(p)

        if not q.isdigit():
            raise ValueError("Only integer values are allowed.")
        q = int(q)

        if p <= 10 or q <= 10:
            raise ValueError("Both p and q need to be greater than 10.")
        
        check_prime(p)
        check_prime(q)

        if p == q:
            raise ValueError("p and q cannot be equal.")

        public, private = generate_keypair(p, q)
        print("Public key is", public)
        print("Private key is", private)

        encrypted_msg = encrypt(public, message)
        print("Encrypted message is:")
        print(''.join(map(lambda x: str(x), encrypted_msg)))
        print("Decrypted message is:")
        print(decrypt(private, encrypted_msg))
    except ValueError as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
