from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
import datetime

# Constants for certificate
SERIAL_NUMBER = 1000  # A fixed serial number for simplicity
NOT_VALID_BEFORE = datetime.datetime(2024, 10, 1)
NOT_VALID_AFTER = datetime.datetime(2024, 10, 31)

def generate_keys():
    """
    Generates or loads an RSA private key from a PEM file. If the key does not exist, it generates a new one,
    saves it to 'private_key.pem', and returns the key object.
    
    Returns:
    - private_key (rsa.RSAPrivateKey): The RSA private key used for signing the certificate.
    """
    try:
        # Try to load an existing private key from a PEM file
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # No password protection for simplicity
            )
    except FileNotFoundError:
        # If no key exists, generate a new RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,  # Standard key size for RSA
        )
        # Save the newly generated key to a PEM file
        with open("private_key.pem", "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()  # Store without encryption
                )
            )
    return private_key

def create_certificate(private_key):
    """
    Creates a self-signed X.509 certificate with the given private key.

    Parameters:
    - private_key (rsa.RSAPrivateKey): The private key used to generate and sign the certificate.

    Returns:
    - cert (x509.Certificate): The generated X.509 certificate.
    """
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Queensland"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Brisbane"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UQ"),
        x509.NameAttribute(NameOID.COMMON_NAME, "uq.com"),
    ])

    cert = x509.CertificateBuilder().subject_name(issuer
    ).issuer_name(issuer
    ).public_key(private_key.public_key()
    ).serial_number(SERIAL_NUMBER 
    ).not_valid_before(NOT_VALID_BEFORE 
    ).not_valid_after(NOT_VALID_AFTER
    ).sign(private_key, hashes.SHA256()
    ).public_bytes(serialization.Encoding.PEM)

    return cert

def main():
    """
    Main function to generate an RSA key and a self-signed certificate, and save the certificate to 'certificate.pem'.
    """
    try:
        private_key = generate_keys()
        cert = create_certificate(private_key)
        # Write the certificate to a PEM file
        with open("certificate.pem", "wb") as cert_file:
            cert_file.write(cert)
            
        print("Certificate created and written to 'certificate.pem'")
    except ValueError as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
