# Secure Password Generator and Decryption

This web application allows users to generate secure passwords and decrypt previously saved passwords using a master key. It provides a simple and secure way to create strong passwords and save them to files for later retrieval.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Features

- Password Generation: Users can generate strong and secure passwords with customizable length and character sets (uppercase letters, lowercase letters, digits, and symbols).
- Password Strength Score: The application calculates the strength score of the generated password, making it easier for users to assess the password's security level.
- Save Password to File: Users have the option to save the generated password to a file, which is encrypted using a master key.
- Password Decryption: Users can decrypt previously saved passwords using the master key.
- Password Strength Score Legend: The application provides a legend explaining the password strength scores for easy reference.

## Requirements

- Python 3.x
- Flask
- cryptography

## Installation

1. Clone the repository:

- git clone
- cd  

2. Install the required packages using pip:

- pip install -r requirements.txt


## Usage

1. Run the application:

- python secure_password_generator.py

2. Access the application in your web browser at `http://localhost:5000/`.

3. Secure Password Generator:
   - Choose the desired password length and character sets.
   - Optionally, select "Save Password to File" and provide a master key for encryption.
   - Click "Generate Password" to get a strong and secure password.

4. Secure Password Decryption:
   - Click on "Press Here To Decrypt Password" to navigate to the decryption page.
   - Upload the encrypted password file and provide the correct master key.
   - Click "Decrypt Password" to reveal the original password.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please feel free to open an issue or create a pull request.

## License

This project is licensed under the [MIT License](LICENSE).



