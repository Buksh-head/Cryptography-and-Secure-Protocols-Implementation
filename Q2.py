def check_prime(num):
    """
    Validates if a given number is a prime.
    
    Parameters:
    - num (int): The number to check for primality.
    
    Raises:
    - ValueError: If num is not a prime number.
    """
    if num <= 1:
        raise ValueError("Not a prime number.")
    if num == 2 or num == 3:
        return True
    if num % 2 == 0 or num % 3 == 0:
        raise ValueError("Not a prime number.")
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            raise ValueError("Not a prime number.")
        i += 6
    return True


def generate_public_key(p, g, private_key):
    """
    Generates a public key for Diffie-Hellman key exchange.
    
    Parameters:
    - p (int): The prime modulus.
    - g (int): The base generator.
    - private_key (int): The private key.
    
    Returns:
    - int: The generated public key.
    """
    
    return pow(g, private_key, p)

def compute_shared_secret(other_public, private_key, p):
    """
    Computes the shared secret using Diffie-Hellman key exchange.
    
    Parameters:
    - other_public (int): The other party's public key.
    - private_key (int): The private key of the current user.
    - p (int): The prime modulus.
    
    Returns:
    - int: The computed shared secret.
    """
    return pow(other_public, private_key, p)

def main():
    """
    Main function to handle user input and execute Diffie-Hellman key exchange.
    """
    try:
        # Input for prime number p
        p = input("Enter prime number p: ")
        if len(p.strip()) == 0:
            raise ValueError("Empty value is not allowed.")
        if not p.isdigit():
            raise ValueError("Only integer values are allowed.")
        p = int(p)
        check_prime(p)

        
        # Input for generator g
        g = input("Enter generator g: ")
        if len(g.strip()) == 0:
            raise ValueError("Empty value is not allowed.")
        if not g.isdigit():
            raise ValueError("Only integer values are allowed.")
        g = int(g)


        # Input for Alice's private key
        alice_private = input("Enter Alice's private key: ")
        if len(alice_private.strip()) == 0:
            raise ValueError("Empty value is not allowed.")
        if not alice_private.isdigit():
            raise ValueError("Only integer values are allowed.")
        alice_private = int(alice_private)
        if alice_private <= 0 or alice_private >= p:
            raise ValueError("Invalid private key.")

        # Input and validation for Bob's private key
        bob_private = input("Enter Bob's private key: ")
        if len(bob_private.strip()) == 0:
            raise ValueError("Empty value is not allowed.")
        if not bob_private.isdigit():
            raise ValueError("Only integer values are allowed.")
        bob_private = int(bob_private)
        if bob_private <= 0 or bob_private >= p:
            raise ValueError("Invalid private key.")
        
        # Generating public keys
        alice_public = generate_public_key(p, g, alice_private)
        bob_public = generate_public_key(p, g, bob_private)

        # Computing shared secrets
        alice_secret = compute_shared_secret(bob_public, alice_private, p)
        bob_secret = compute_shared_secret(alice_public, bob_private, p)

        # Printing all keys and shared secrets
        print(f"Alice's private key: {alice_private}")
        print(f"Bob's private key: {bob_private}")
        print(f"Alice's public key: {alice_public}")
        print(f"Bob's public key: {bob_public}")
        print(f"Shared secret: {alice_secret} (Alice) | {bob_secret} (Bob)")
    except ValueError as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
