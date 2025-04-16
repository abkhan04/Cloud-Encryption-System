# Import necessary modules
from collections import defaultdict
from dotenv import load_dotenv
import datetime
import os

# Dropbox API and error handling
import dropbox
import dropbox.exceptions

# Flask framework for web application
from flask import Flask, render_template, request, session, redirect, url_for, flash, make_response

# Cryptographic tools
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

# Load environment variables from a .env file
load_dotenv()

# Get the Dropbox API key from environment variables
DROPBOX_API_KEY = os.environ.get('DROPBOX_API_KEY')

# Initialise Dropbox client
dbx = dropbox.Dropbox(DROPBOX_API_KEY)

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = 'secret_key'  # Secret key used for sessions

# In-memory storage for users, files, and groups
users = {}  # {username: [password, public_key, private_key, certificate]}
file_store = defaultdict(lambda: defaultdict(list))  # {username: {filename: encrypted_key}}
user_groups = defaultdict(list)  # {username: [group_member_usernames]}


def create_certificate():
    """
    Generate an RSA key pair and a self-signed certificate.
    
    Returns:
        tuple: (public_key, private_key, certificate)
    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Get public key
    public_key = private_key.public_key()

    # Define certificate subject and issuer (self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Leinster"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Dublin"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
    ])

    # Build and sign the certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False,
        # Sign our certificate with our private key
    ).sign(private_key, hashes.SHA256())

    return public_key, private_key, cert


# Hybrid Encryption: Encrypts the message and the symmetric key
def hybrid_encrypt(message: bytes, public_key) -> (bytes, bytes):
    """
    Encrypt a message using a hybrid approach.
    The message is encrypted with a symmetric key, which is then encrypted with the RSA public key.

    Args:
        message (str): Plain text message to encrypt.
        public_key: RSA public key object.

    Returns:
        tuple: (encrypted_message (bytes), encrypted_symmetric_key (bytes))
    """
    # Generate a symmetric Fernet key
    symmetric_key = Fernet.generate_key()
    
    # Encrypt message with Fernet symmetric encryption
    fernet = Fernet(symmetric_key)
    encrypted_message = fernet.encrypt(message)

    # Encrypt the symmetric key using RSA public key with OAEP padding
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_message, encrypted_symmetric_key


# Hybrid Decryption: Decrypts the symmetric key with the RSA private key then decrypts the message
def hybrid_decrypt(encrypted_message: bytes, encrypted_symmetric_key: bytes, private_key) -> str:
    """
    Decrypt the encrypted symmetric key with the RSA private key and use it to decrypt the message.

    Args:
        encrypted_message (bytes): The message encrypted with a symmetric key.
        encrypted_symmetric_key (bytes): The symmetric key encrypted with RSA.
        private_key: RSA private key object.

    Returns:
        str: Decrypted plain text message.
    """
    # Decrypt the symmetric key using the RSA private key
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the message using Fernet with the decrypted symmetric key
    fernet = Fernet(symmetric_key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()

    return decrypted_message


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handle user registration. Generates a key pair and certificate for each user.
    """
    # If the user is already logged in, redirect them to the dashboard page.
    if 'username' in session:
        flash('You are already logged in.')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        # Retrieve registration form data
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Check that all fields are filled
        if not username or not password:
            flash('Please provide both a username and a password.')
            return redirect(url_for('register'))
        
        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match. Please try again.')
            return redirect(url_for('register'))
        
        # Check if the username is already taken
        if username in users:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('register'))
        
        # Create public key, private key, and certificate
        public_key, private_key, certificate = create_certificate()
        
        # Register the new user (store credentials in the in-memory dictionary)
        users[username] = [password, public_key, private_key, certificate]

        return redirect(url_for('login'))
    
    # Display the registration form on a GET request.
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handle user login by verifying credentials.
    """
    # If the user is already logged in, redirect them to the dashboard page.
    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Retrieve credentials from the login form.
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Validate the user's credentials.
        if username in users and users[username][0] == password:
            session['username'] = username  # Mark the user as logged in.
            flash('Logged in successfully.')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.')
            return redirect(url_for('login'))
    
    # Render the login page for a GET request.
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    """
    Display user dashboard showing accessible files and group members.
    """
    # Only allow access if the user is logged in.
    if 'username' not in session:
        flash('Please log in to access this page.')
        return redirect(url_for('login'))
    
    username = session['username']
            
    # Render the protected page with the username.
    return render_template('dashboard.html', username=session['username'], files=file_store[username], group=user_groups[username])


@app.route('/upload_file', methods=['POST'])
def upload_file():
    """
    Upload a file to Dropbox, encrypting it for all users in the sender's group.
    """
    # Only allow access if the user is logged in.
    if 'username' not in session:
        flash('Please log in to access this page.')
        return redirect(url_for('login'))

    # Check if a file was uploaded
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('dashboard'))
    
    username = session['username']

    try:
        # Send to all users in the group
        for user in user_groups[username]:
            public_key = users[user][1]
            cert = users[user][3]

            # Verfiy the public key
            public_key.verify(
                signature=cert.signature,
                data=cert.tbs_certificate_bytes,
                padding=padding.PKCS1v15(),
                algorithm=cert.signature_hash_algorithm,
            )

            # Encrypt the message and the key
            encrypted_message, encrypted_symmetric_key = hybrid_encrypt(file.read(), public_key)

            # Upload the file to the specified Dropbox destination path
            dbx.files_upload(encrypted_message, f'/{user}/{file.filename}')
            file_store[user][file.filename] = encrypted_symmetric_key

            print(f'File "{file.filename}" uploaded successfully to /{user}/{file.filename}.')
    except dropbox.exceptions.ApiError as err:
        print(f'API error encountered: {err}')
    except Exception as exc:
        print(f'An error occurred: {exc}')

    return redirect(url_for('dashboard'))


@app.route('/download_file/<filename>', methods=['GET'])
def download_file(filename):
    """
    Download and decrypt a file from Dropbox for the logged-in user.
    """
    # Only allow access if the user is logged in.
    if 'username' not in session:
        flash('Please log in to access this page.')
        return redirect(url_for('login'))

    username = session['username']
    
    # Construct the Dropbox file path.
    # This example assumes that the file is stored in the user's folder.
    dropbox_path = f'/{username}/{filename}'

    try:
        # Call the Dropbox API to download the file.
        metadata, response = dbx.files_download(dropbox_path)
        
        # Decrypt the message
        private_key = users[username][2]
        encrypted_symmetric_key = file_store[username][filename]

        decrypted_message = hybrid_decrypt(response.content, encrypted_symmetric_key, private_key)
        
        # Create a Flask response with appropriate headers to prompt a download.
        download_response = make_response(decrypted_message)
        download_response.headers.set('Content-Disposition', 'attachment', filename=filename)
        download_response.headers.set('Content-Type', 'application/octet-stream')
        
        return download_response
    except dropbox.exceptions.ApiError as err:
        print(f'API error encountered: {err}')
    except Exception as exc:
        print(f'An error occurred: {exc}')

    return redirect(url_for('dashboard'))


@app.route('/add_to_group', methods=['POST'])
def add_to_group():
    """
    Add a user to the current user's sharing group.
    """
    # Only allow access if the user is logged in.
    if 'username' not in session:
        flash('Please log in to access this page.')
        return redirect(url_for('login'))
    
    member = request.form.get('member')

    if member in users:
        user_groups[session['username']].append(member)

    return redirect(url_for('dashboard'))


@app.route('/remove_from_group', methods=['POST'])
def remove_from_group():
    """
    Remove a user from the current user's sharing group.
    """
    if 'username' not in session:
        flash('Please log in to access this page.')
        return redirect(url_for('login'))

    member = request.form.get('member')
    user_groups[session['username']].remove(member)

    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    """
    Logout the current user by clearing their session.
    """
    session.pop('username', None)
    flash('Logged out successfully.')
    return redirect(url_for('login'))


if __name__ == '__main__':
    # Create test users with certificates and mutual group membership
    public_key, private_key, cert = create_certificate()
    users['test'] = ['test', public_key, private_key, cert]

    public_key, private_key, cert = create_certificate()
    users['test2'] = ['test', public_key, private_key, cert]

    user_groups['test2'].append('test')
    user_groups['test'].append('test2')

    # Start Flask server
    app.run(debug=True)
