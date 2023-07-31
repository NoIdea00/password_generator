import base64
import random
import string
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_password(length=12, uppercase=True, digits=True, symbols=True):
    characters = string.ascii_letters
    if uppercase:
        characters += string.ascii_uppercase
    if digits:
        characters += string.digits
    if symbols:
        characters += string.punctuation

    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def password_strength(password):
    strength = 0
    if any(char.isdigit() for char in password):
        strength += 1
    if any(char.isupper() for char in password):
        strength += 1
    if any(char.islower() for char in password):
        strength += 1
    if any(char in string.punctuation for char in password):
        strength += 1
    return strength

def generate_fernet_key(master_key):
    # Use PBKDF2 to derive a 32-byte key from the provided master_key
    password = master_key.encode()
    salt = b'\x00' * 16  # You can use a random salt for added security if you want
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # You can adjust the number of iterations as needed
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def save_password(password, filename, master_key):
    key = generate_fernet_key(master_key)
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(password.encode())

    with open(filename, "wb") as file:
        file.write(encrypted_password)

def decrypt_password(filename, master_key):
    key = generate_fernet_key(master_key)
    cipher_suite = Fernet(key)

    with open(filename, "rb") as file:
        encrypted_password = file.read()

    decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
    return decrypted_password


def main():
    print("Advanced Password Generator")
    print("----------------------------")

    while True:
        try:
            password_length = int(input("Enter the desired password length (default is 12): ") or 12)
            use_uppercase = input("Include uppercase letters? (Y/N, default is Y): ").upper() in ("Y", "YES")
            use_digits = input("Include digits? (Y/N, default is Y): ").upper() in ("Y", "YES")
            use_symbols = input("Include symbols? (Y/N, default is Y): ").upper() in ("Y", "YES")
            break
        except ValueError:
            print("Invalid input. Please enter a valid number.")

    generated_password = generate_password(password_length, use_uppercase, use_digits, use_symbols)
    password_strength_score = password_strength(generated_password)

    print("\nGenerated Password:", generated_password)
    print("Password Strength: {}/4".format(password_strength_score))

    save_password_option = input("\nDo you want to save this password? (Y/N): ").upper() in ("Y", "YES")
    if save_password_option:
        filename = input("Enter the filename to save the password (e.g., 'passwords.txt'): ")
        master_key = getpass.getpass("Enter the master key for encryption: ")
        save_password(generated_password, filename, master_key)  # Include the master_key argument here
        print("Password saved successfully!")

    decrypt_password_option = input("\nDo you want to decrypt a password from a file? (Y/N): ").upper() in ("Y", "YES")
    if decrypt_password_option:
        filename = input("Enter the filename containing the encrypted password: ")
        master_key = getpass.getpass("Enter the master key for decryption: ")
        decrypted_password = decrypt_password(filename, master_key)
        print("Decrypted Password:", decrypted_password)

if __name__ == "__main__":
    main()


