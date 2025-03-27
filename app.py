from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure secret key for your app

# Ensure you have your SQLite database initialized and connected
DATABASE = 'secure_file_storage.db'

# Function to encrypt file using hybrid encryption (AES + RSA)
def encrypt_file(file_path, public_key_path):
    # Generate a random AES key
    aes_key = get_random_bytes(16)
    
    # Encrypt the AES key using RSA
    recipient_key = RSA.import_key(open(public_key_path).read())
    rsa_cipher = PKCS1_OAEP.new(recipient_key)
    enc_aes_key = rsa_cipher.encrypt(aes_key)

    # Encrypt the file data using AES
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    
    with open(file_path, "rb") as f:
        file_data = f.read()
    
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)

    # Save encrypted data
    enc_file_path = file_path + ".enc"
    with open(enc_file_path, "wb") as f:
        f.write(enc_aes_key + cipher_aes.nonce + tag + ciphertext)
    
    print("File Encrypted Successfully!")
    return enc_file_path  # Returning the encrypted file path

# Function to decrypt file using AES + RSA
def decrypt_file(encrypted_file_path, private_key_path):
    with open(encrypted_file_path, "rb") as f:
        enc_data = f.read()

    private_key = RSA.import_key(open(private_key_path).read())
    rsa_cipher = PKCS1_OAEP.new(private_key)

    enc_aes_key = enc_data[:256]  # First 256 bytes are RSA encrypted AES key
    nonce = enc_data[256:272]  # Next 16 bytes are nonce
    tag = enc_data[272:288]  # Next 16 bytes are authentication tag
    ciphertext = enc_data[288:]  # Rest is encrypted data

    # Decrypt AES key
    aes_key = rsa_cipher.decrypt(enc_aes_key)

    # Decrypt file data
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    decrypted_file_path = encrypted_file_path.replace(".enc", "_decrypted" + os.path.splitext(encrypted_file_path)[1])
    with open(decrypted_file_path, "wb") as f:
        f.write(decrypted_data)

    print("File Decrypted Successfully!")
    return decrypted_file_path  # Returning the decrypted file path

# Database connection function
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# User authentication: Check login credentials
def check_user_credentials(username, password):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    conn.close()
    return user

# Root route (home page)
@app.route('/')
def home():
    return redirect(url_for('login'))  # Redirects to login page

# Register user
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()
        flash("Registration successful! Please log in.")
        return redirect(url_for('login'))
    return render_template('register.html')

# Login user
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = check_user_credentials(username, password)
        if user:
            session['user'] = username
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials. Please try again.")
    return render_template('login.html')

# Dashboard: Upload and Download files
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST' and 'file' in request.files:
        file = request.files['file']
        if file:
            file_path = os.path.join('uploads', file.filename)
            file.save(file_path)

            # Encrypt the file after uploading
            enc_file_path = encrypt_file(file_path, "public.pem")
            
            # Save file info in the database
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO files (user_id, file_name, file_path) VALUES (?, ?, ?)",
                           (session['user'], file.filename, enc_file_path))
            conn.commit()
            conn.close()
            flash("File uploaded and encrypted successfully!")
            return redirect(url_for('dashboard'))

    # Query the database to get the uploaded files for the logged-in user
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM files WHERE user_id=?", (session['user'],))
    files = cursor.fetchall()
    conn.close()

    # Render the dashboard template and pass the files to it
    return render_template('dashboard.html', files=files)


                        


# Download file
@app.route('/download/<int:file_id>')
def download_file(file_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM files WHERE id=?", (file_id,))
    file = cursor.fetchone()
    conn.close()

    if file:
        encrypted_file_path = file['file_path']
        decrypted_file_path = decrypt_file(encrypted_file_path, "private.pem")

        # Get the actual file name from the database (not 'swathi')
        filename = file['file_name']  # This retrieves the filename stored in the database

        return send_file(decrypted_file_path, as_attachment=True, download_name=filename)

    flash("File not found.")
    return redirect(url_for('dashboard'))


# Logout user
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))

