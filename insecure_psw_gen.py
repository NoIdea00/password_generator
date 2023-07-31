import random
import string

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

def main():
    print("Password Generator")
    print("------------------")

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

    print("\nGenerated Password:", generated_password)

if __name__ == "__main__":
    main()
