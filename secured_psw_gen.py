import base64
import random
import string
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, abort, render_template, request, send_file, flash, redirect, url_for
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a secure random secret key

def generate_password(length=12, uppercase=True, lowercase=True, digits=True, symbols=True):
    characters = ""
    if uppercase:
        characters += string.ascii_uppercase
    if lowercase:
        characters += string.ascii_lowercase
    if digits:
        characters += string.digits
    if symbols:
        characters += string.punctuation

    if not characters:
        raise ValueError("No character set selected for password generation.")

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
    password = master_key.encode()
    salt = b'\x00' * 16
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
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

def decrypt_password(password_file, master_key_decrypt):
    key = generate_fernet_key(master_key_decrypt)
    cipher_suite = Fernet(key)

    encrypted_password = password_file.read()

    try:
        decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
    except Exception as e:
        decrypted_password = None

    return decrypted_password

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'txt'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS    

@app.route('/', methods=['GET', 'POST'])
def password_generator():
    generated_password = ""  # Define with default value
    password_strength_score = 0  # Define with default value
    filename = None  # Initialize filename

    if request.method == 'POST':
        password_length = int(request.form.get('password_length', 12))
        use_uppercase = bool(request.form.get('use_uppercase'))
        use_lowercase = bool(request.form.get('use_lowercase'))
        use_digits = bool(request.form.get('use_digits'))
        use_symbols = bool(request.form.get('use_symbols'))

        characters = ""
        if use_uppercase:
            characters += string.ascii_uppercase
        if use_lowercase:
            characters += string.ascii_lowercase
        if use_digits:
            characters += string.digits
        if use_symbols:
            characters += string.punctuation

        try:
            generated_password = generate_password(password_length, use_uppercase, use_lowercase, use_digits, use_symbols)
            password_strength_score = password_strength(generated_password)
        except ValueError as e:
            flash(str(e), "error")

        save_password_option = request.form.get('save_password', False)
        if save_password_option:
            master_key = request.form.get('master_key', '')
            filename = os.path.join(os.getcwd(), "generated_password.txt")
            save_password(generated_password, filename, master_key)
            flash("Password saved to file.", "success")

    return render_template('index.html', generated_password=generated_password, password_strength_score=password_strength_score, filename=filename)

@app.route('/download_password', methods=['GET'])
def download_password():
    filename = request.args.get('filename')
    if filename:
        return send_file(filename, as_attachment=True)
    else:
        flash("No password file to download.", "error")
        return redirect(url_for('password_generator'))
    
@app.route('/decrypt', methods=['GET', 'POST'])
def password_decryption():
    decrypted_password = None  # Initialize with None
    invalid_file_extension = False  # Initialize with False
    file_extension = None  # Initialize with None

    if request.method == 'POST':
        master_key_decrypt = request.form.get('master_key_decrypt', '')
        if 'password_file' not in request.files:
            flash('No file part', "error")
            return redirect(request.url)

        password_file = request.files['password_file']
        if password_file.filename == '':
            flash('No selected file', "error")
            return redirect(request.url)

        if not allowed_file(password_file.filename):
            invalid_file_extension = True
        else:
            # Get the file extension only if it is a valid file
            file_extension = password_file.filename.rsplit('.', 1)[1].lower()

            decrypted_password = decrypt_password(password_file, master_key_decrypt)
            if decrypted_password is None:
                flash("Decryption failed. Please check the master key and the selected file.", "error")
            else:
                flash("Password decrypted successfully.", "success")

    return render_template('decrypt.html', decrypted_password=decrypted_password,
                           invalid_file_extension=invalid_file_extension, file_extension=file_extension)

@app.route('/generated_password.txt', methods=['GET'])
def serve_generated_password():
    # Get the 'file_path' parameter from the URL query string
    file_path = request.args.get('file_path')

    # Validate the 'file_path' parameter to prevent directory traversal
    if file_path and not os.path.isabs(file_path) and '../' not in file_path:
        # Set the directory root for generated_password.txt
        directory_root = os.path.join(os.getcwd(), "saved")

        # Construct the full file path
        full_file_path = os.path.join(directory_root, file_path)

        # Check if the file exists and is within the intended directory
        if os.path.exists(full_file_path) and os.path.commonpath([full_file_path, directory_root]) == directory_root:
            # Return the file specified by the 'file_path' parameter as plain text (for demo purposes only)
            return send_file(full_file_path, mimetype='text/plain')
        else:
            abort(403)  # Return a 403 Forbidden status for unauthorized access attempts
    else:
        abort(400)  # Return a 400 Bad Request status for invalid file paths


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
