import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
import sys

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_signature(file_path, private_key):
    with open(file_path, 'rb') as file:
        document_content = file.read()

    hash_object = hashlib.sha3_256(document_content)
    signature = private_key.sign(
        hash_object.digest(),
        padding.PKCS1v15(),
        hashes.SHA3_256()
    )
    return signature

def save_key_to_file(key, file_name, key_format):
    if key_format == PublicFormat.SubjectPublicKeyInfo:
        key_pem = key.public_bytes(
            encoding=Encoding.PEM,
            format=key_format
        )
    else:
        key_pem = key.private_bytes(
            encoding=Encoding.PEM,
            format=key_format,
            encryption_algorithm=NoEncryption()
        )
    with open(file_name, 'wb') as file:
        file.write(key_pem)

def sign_document(private_key, file_path):
    signature_file = 'signature.bin'

    signature = generate_signature(file_path, private_key)

    with open(signature_file, 'wb') as file:
        file.write(signature)

if __name__ == "__main__":
    private_key, public_key = generate_rsa_key_pair()
    save_key_to_file(public_key, 'public_key.pem', PublicFormat.SubjectPublicKeyInfo)
    save_key_to_file(private_key, 'private_key.pem', PrivateFormat.PKCS8)
    file_path = input("Enter the path to the file to be signed: ")
    sign_document(private_key, file_path)
    print("File signed successfully.")
