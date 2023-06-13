import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
import sys

def verify_signature(file_path, signature_file, public_key):
    with open(file_path, 'rb') as file:
        document_content = file.read()

    hash_object = hashlib.sha3_256(document_content)
    signature = open(signature_file, 'rb').read()

    try:
        public_key.verify(
            signature,
            hash_object.digest(),
            padding.PKCS1v15(),
            hashes.SHA3_256()
        )
        return True
    except Exception:
        return False

def load_public_key_from_file(file_name):
    with open(file_name, 'rb') as file:
        public_key_pem = file.read()

    public_key = load_pem_public_key(public_key_pem)
    return public_key

if __name__ == "__main__":
    public_key = load_public_key_from_file('public_key.pem')
    file_path = input("Enter the path to the signed file: ")
    is_valid = verify_signature(file_path, 'signature.bin', public_key)
    if is_valid:
        print("The signature is valid.")
    else:
        print("The signature is not valid.")
