import documentSigning8
import signatureVerification8

while True:
    print("1. Sign a file")
    print("2. Check a signature")
    print("3. Exit")

    choice = input("Enter your choice (1, 2, or 3): ")

    if choice == "1":
        private_key, public_key = documentSigning8.generate_rsa_key_pair()
        documentSigning8.save_key_to_file(public_key, 'public_key.pem', documentSigning8.PublicFormat.SubjectPublicKeyInfo)
        documentSigning8.save_key_to_file(private_key, 'private_key.pem', documentSigning8.PrivateFormat.PKCS8)
        file_path = input("Enter the path to the file to be signed: ")
        documentSigning8.sign_document(private_key, file_path)
        print("File signed successfully.")
        print()

    elif choice == "2":
        public_key = signatureVerification8.load_public_key_from_file('public_key.pem')
        file_path = input("Enter the path to the signed file: ")
        is_valid = signatureVerification8.verify_signature(file_path, 'signature.bin', public_key)
        if is_valid:
            print("The signature is valid.")
        else:
            print("The signature is not valid.")
        print()

    elif choice == "3":
        break

    else:
        print("Invalid choice. Please try again.")
        print()
