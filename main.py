import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


class CryptoBlockchainApp:
    def __init__(self):
        # Dictionary to store vehicles: {number_plate: {"owner": str, "model": str}}
        self.vehicle_registry = {}
        self.private_key = None
        self.public_key = None

    def generate_sha256(self):
        print("\n--- SHA-256 Hashing ---")
        message = input("Enter the message to hash: ").strip()
        if not message:
            print("❌ Error: Message cannot be empty.")
            return

        sha256_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()
        print(f"✅ SHA-256 Hash:\n{sha256_hash}")

    def digital_signature_flow(self):
        print("\n--- Digital Signature (RSA) ---")
        
        # 1. Generate Public-Private Key Pair
        print("Generating 2048-bit RSA key pair...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        print("✅ Key pair generated successfully.")

        # 2. Input Message
        message = input("\nEnter the message to sign: ").strip()
        if not message:
            print("❌ Error: Message cannot be empty.")
            return
        message_bytes = message.encode('utf-8')

        # 3. Sign Message using Private Key
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(f"\n✍️ Digital Signature (Hex):\n{signature.hex()[:64]}... [truncated]")

        # 4. Verify Signature using Public Key
        print("\n--- Signature Verification ---")
        verify_choice = input("Verify original message (1) or test tampered message (2)? [1/2]: ").strip()
        
        if verify_choice == '2':
            test_message = input("Enter a altered/tampered message to test verification: ").encode('utf-8')
        else:
            test_message = message_bytes

        try:
            self.public_key.verify(
                signature,
                test_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("✅ Verification Result: VALID (Signature matches the message and public key).")
        except InvalidSignature:
            print("❌ Verification Result: INVALID (Message was altered or signature does not match).")

    def register_vehicle(self):
        print("\n--- Register Vehicle ---")
        plate = input("Enter Number Plate (e.g., MH12AB1234): ").strip().upper()
        
        # Input validation: empty check & duplicate check
        if not plate:
            print("❌ Error: Number plate cannot be empty.")
            return
        if plate in self.vehicle_registry:
            print(f"❌ Error: Vehicle with number plate '{plate}' is already registered!")
            return

        owner = input("Enter Owner Name: ").strip()
        model = input("Enter Vehicle Model: ").strip()

        if not owner or not model:
            print("❌ Error: Owner name and vehicle model cannot be empty.")
            return

        self.vehicle_registry[plate] = {
            "owner": owner,
            "model": model
        }
        print(f"✅ Vehicle '{plate}' registered successfully!")

    def retrieve_vehicle(self):
        print("\n--- Retrieve Vehicle Details ---")
        plate = input("Enter Number Plate to search: ").strip().upper()

        if not plate:
            print("❌ Error: Please enter a valid number plate.")
            return

        vehicle = self.vehicle_registry.get(plate)
        if vehicle:
            print(f"\n🚗 Vehicle Found:")
            print(f"   Number Plate : {plate}")
            print(f"   Owner Name   : {vehicle['owner']}")
            print(f"   Model        : {vehicle['model']}")
        else:
            print(f"❌ Error: No vehicle found with number plate '{plate}'.")

    def run(self):
        while True:
            print("\n" + "=" * 45)
            print("  CRYPTOGRAPHY & BLOCKCHAIN CONSOLE APP")
            print("=" * 45)
            print("1. Generate SHA-256 Hash")
            print("2. Create & Verify Digital Signature")
            print("3. Register a Vehicle")
            print("4. Retrieve Vehicle Details")
            print("5. Exit")
            print("=" * 45)

            choice = input("Select an option (1-5): ").strip()

            if choice == '1':
                self.generate_sha256()
            elif choice == '2':
                self.digital_signature_flow()
            elif choice == '3':
                self.register_vehicle()
            elif choice == '4':
                self.retrieve_vehicle()
            elif choice == '5':
                print("Exiting application. Goodbye!")
                break
            else:
                print("❌ Invalid choice. Please select a number between 1 and 5.")


if __name__ == "__main__":
    app = CryptoBlockchainApp()
    app.run()