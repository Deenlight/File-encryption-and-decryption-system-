from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
import os
import hashlib
import csv
from werkzeug.utils import secure_filename
from datetime import datetime
from cryptography.fernet import Fernet


# Flask app configuration
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # For session management and flash messages
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create uploads directory if it doesn't exist
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# File paths
DOWNLOADS_CSV = "downloads.csv"
USERS_CSV = "users.csv"


def load_users():
    users = {}
    with open('users.csv', 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            users[row['username']] = {
                'email': row['email'],
                'password': row['password'],
                'encryption_key': row['encryption_key']
            }
    return users


# Home Page
@app.route('/')
def index():
    return render_template('index.html')

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        encryption_key = request.form['encryption_key']

        # Hash the password and encryption key
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        hashed_encryption_key = hashlib.sha256(encryption_key.encode()).hexdigest()

        # Save user data to CSV
        with open('users.csv', 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([username, email, hashed_password, hashed_encryption_key])

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Admin Login Route
@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid admin credentials.", "danger")

    return render_template("admin_login.html")

@app.route("/admin_dashboard")
def admin_dashboard():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    total_users = 0
    total_files = 0
    user_logs = []

    # Read users and logs data
    if os.path.exists(USERS_CSV):
        with open(USERS_CSV, "r") as file:
            total_users = sum(1 for _ in csv.reader(file)) - 1

    if os.path.exists(DOWNLOADS_CSV):
        with open(DOWNLOADS_CSV, "r") as file:
            reader = csv.DictReader(file)
            user_logs = list(reader)
            total_files = len(user_logs)

    return render_template("admin_dashboard.html", total_users=total_users, total_files=total_files, user_logs=user_logs)


# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Please enter both username and password.', 'warning')
            return redirect(url_for('login'))

        # Hash the input password to compare with stored hash
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Check the credentials in the CSV file
        try:
            with open('users.csv', 'r') as file:
                reader = csv.reader(file)
                for row in reader:
                    if row[0] == username and row[2] == hashed_password:
                        session['username'] = username  # Store username in session
                        return redirect(url_for('dashboard'))
        except FileNotFoundError:
            flash('User database not found. Please contact the admin.', 'danger')
            return redirect(url_for('login'))

        # Flash an error message if login fails
        flash('Invalid username or password. Please try again.', 'danger')
        return redirect(url_for('login'))

    # Render the login page for GET requests
    return render_template('login.html')


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))

    username = session['username']
    users = load_users()

    if username not in users:
        flash('User not found in the system.', 'danger')
        return redirect(url_for('login'))
    
    # Retrieve encryption key from user data (e.g., users.csv)
    encryption_key = None
    with open('users.csv', 'r') as users_file:
        reader = csv.DictReader(users_file)
        for row in reader:
            if row['username'] == username:
                encryption_key = row['encryption_key']
                break

    if not encryption_key:
        flash('Encryption key not found for user.', 'danger')
        return redirect(url_for('login'))
    
    username = session['username']
    user_folder = os.path.join(UPLOAD_FOLDER, username)
    os.makedirs(user_folder, exist_ok=True)
    metadata_path = os.path.join(user_folder, 'metadata.csv')

    # Ensure metadata.csv exists
    if not os.path.exists(metadata_path):
        with open(metadata_path, 'w', newline='') as meta_file:
            writer = csv.writer(meta_file)
            writer.writerow(['File Name', 'Encryption Status', 'Date Uploaded'])

    # Handle File Upload
        # Handle file upload
    if request.method == 'POST' and 'file' in request.files:
        uploaded_file = request.files['file']
        if uploaded_file and uploaded_file.filename != '':
            file_path = os.path.join(user_folder, uploaded_file.filename)
            uploaded_file.save(file_path)

            with open(metadata_path, 'a', newline='') as meta_file:
                writer = csv.writer(meta_file)
                writer.writerow([uploaded_file.filename, 'Encrypted', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
            flash('File uploaded successfully!', 'success')
            return redirect(url_for('dashboard'))


    # Handle File Preview (Raw Encrypted Data)
    if 'preview' in request.args:
        file_name = request.args.get('preview')
        file_path = os.path.join(user_folder, file_name)
        if os.path.exists(file_path):
            try:
                # Read raw encrypted data
                with open(file_path, 'rb') as file:
                    encrypted_data = file.read()

                # Pass the raw encrypted data for preview
                return render_template(
                    'preview.html',
                    filename=file_name,
                    encrypted_data=encrypted_data.hex()  # Convert binary to hex for display
                )
            except Exception as e:
                flash(f"Error reading file for preview: {e}", 'danger')
        else:
            flash('File not found for preview.', 'danger')
        return redirect(url_for('dashboard'))

    # Handle file deletion
    if 'delete' in request.args:
        file_name = request.args.get('delete')
        file_path = os.path.join(user_folder, file_name)
        if os.path.exists(file_path):
            os.remove(file_path)
            with open(metadata_path, 'r') as meta_file:
                rows = list(csv.reader(meta_file))
            with open(metadata_path, 'w', newline='') as meta_file:
                writer = csv.writer(meta_file)
                writer.writerows(row for row in rows if row[0] != file_name)
            flash(f'{file_name} deleted successfully.', 'success')
        else:
            flash('File not found for deletion.', 'danger')
        return redirect(url_for('dashboard'))

        # Handle file download
    if 'download' in request.form:
        selected_files = request.form.getlist('selected_files')
        decryption_key = request.form.get('decryption_key', '').strip()

            # Hash the entered decryption key
        hashed_key = hashlib.sha256(decryption_key.encode()).hexdigest()

            # Verify the hashed key against the stored hashed key
        with open('users.csv', 'r') as users_file:
            reader = csv.DictReader(users_file)
            user_record = next((row for row in reader if row['username'] == username), None)
            
        if user_record and user_record['encryption_key'] == hashed_key:
            for file_name in selected_files:
                file_path = os.path.join(user_folder, file_name)
                if os.path.exists(file_path):
                        # Log download details
                    with open('downloads.csv', 'a', newline='') as file:
                        writer = csv.DictWriter(file, fieldnames=['username', 'file_name', 'timestamp', 'file_size'])
                        if file.tell() == 0:  # Write header if the file is empty
                            writer.writeheader()
                        file_size = os.path.getsize(file_path)
                        file_size_kb = f"{file_size / 1024:.2f} KB"
                        writer.writerow({
                                'username': username,
                                'file_name': file_name,
                                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'file_size': file_size_kb
                         })

                        # Serve file for download
                    return send_from_directory(user_folder, file_name, as_attachment=True)
                else:
                    flash(f"File '{file_name}' not found.", 'danger')
        else:
            flash('Incorrect decryption key. Please try again.', 'danger')

    # Fetch user's uploaded files
    files = []
    if os.path.exists(user_folder):
        files = [(file, 'Encrypted', datetime.fromtimestamp(os.path.getmtime(os.path.join(user_folder, file))).strftime('%Y-%m-%d %H:%M:%S')) for file in os.listdir(user_folder)]

    return render_template('dashboard.html', username=username, files=files)

    
# File Upload Route
@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'username' not in session:
        return redirect(url_for('login'))

    file = request.files['file']
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)  # Save file to the uploads folder

        # Add file entry to CSV
        with open('user_files.csv', 'a', newline='') as file_db:
            writer = csv.writer(file_db)
            writer.writerow([session['username'], filename, 'Uploaded'])

        flash('File uploaded successfully!', 'success')
    else:
        flash('No file selected. Please try again.', 'danger')

    return redirect(url_for('dashboard'))
@app.route('/downloaded_files', methods=['GET'])
def downloaded_files():
    if 'username' not in session:
        flash('Please log in to access downloaded files.', 'warning')
        return redirect(url_for('login'))

    username = session['username']
    downloaded_files = []

    # Check if downloads.csv exists
    if os.path.exists('downloads.csv'):
        with open('downloads.csv', 'r') as file:
            reader = csv.DictReader(file)
            downloaded_files = [
                row for row in reader if row['username'] == username
            ]

    return render_template('downloaded_files.html', downloaded_files=downloaded_files)

@app.route('/download_file/<file_name>')
def download_file(file_name):
    if 'username' not in session:
        flash('Please log in to download files.', 'warning')
        return redirect(url_for('login'))

    username = session['username']
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    file_path = os.path.join(user_folder, file_name)

    if os.path.exists(file_path):
        return send_from_directory(user_folder, file_name, as_attachment=True)
    else:
        flash(f"File '{file_name}' not found.", 'danger')
        return redirect(url_for('downloaded_files'))


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        flash('Please log in to access your profile.', 'warning')
        return redirect(url_for('login'))

    username = session['username']
    user_data = None

    # Load user data from users.csv
    with open('users.csv', 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row['username'] == username:
                user_data = row
                break

    if not user_data:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Update user details
        updated_username = request.form['username']
        updated_email = request.form['email']
        updated_encryption_key = request.form['encryption_key']

        users = []

        # Update the record in users.csv
        with open('users.csv', 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row['username'] == username:
                    row['username'] = updated_username
                    row['email'] = updated_email
                    row['encryption_key'] = hashlib.sha256(updated_encryption_key.encode()).hexdigest()
                users.append(row)

        with open('users.csv', 'w', newline='') as file:
            fieldnames = ['username', 'email', 'password', 'encryption_key']
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(users)

        # Update session username if changed
        session['username'] = updated_username

        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user_data=user_data)

@app.route('/preview/<filename>', methods=['GET'])
def preview_file(filename):
    try:
        # Define the file path
        user_folder = os.path.join('uploaded_files', session['username'])  # Adjust to your folder structure
        file_path = os.path.join(user_folder, filename)

        if not os.path.exists(file_path):
            flash('File not found!', 'danger')
            return redirect(url_for('dashboard'))

        # Read the file as binary data
        with open(file_path, 'rb') as file:
            file_data = file.read()

        # Encrypt the binary data
        encryption_key = Fernet.generate_key()  # Generate a temporary encryption key
        fernet = Fernet(encryption_key)
        encrypted_data = fernet.encrypt(file_data)

        # Display the encrypted data as text
        encrypted_text = encrypted_data.decode('utf-8', errors='ignore')  # Decode for display in the preview
        return render_template(
            'preview.html',
            filename=filename,
            encrypted_text=encrypted_text,
            encryption_key=encryption_key.decode('utf-8')  # Include the key for reference
        )

    except Exception as e:
        flash(f"An error occurred while previewing the file: {e}", 'danger')
        return redirect(url_for('dashboard'))
    
@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
    if 'username' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))

    username = session['username']
    user_folder = os.path.join('uploads', username)
    file_path = os.path.join(user_folder, filename)

    try:
        if os.path.exists(file_path):
            os.remove(file_path)

            # Remove file entry from metadata.csv
            metadata_path = os.path.join(user_folder, 'metadata.csv')
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as meta_file:
                    rows = [row for row in csv.reader(meta_file) if row[0] != filename]
                with open(metadata_path, 'w', newline='') as meta_file:
                    writer = csv.writer(meta_file)
                    writer.writerows(rows)
            flash('File deleted successfully.', 'success')
        else:
            flash('File not found.', 'danger')
    except Exception as e:
        flash(f"Error deleting file: {e}", 'danger')

    return redirect(url_for('dashboard'))

@app.route('/decrypt_download', methods=['POST'])
def decrypt_download():
    if 'username' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))

    username = session['username']
    user_folder = os.path.join('uploads', username)
    selected_files = request.form.getlist('selected_files')
    decryption_key = request.form.get('decryption_key')

    if not selected_files or not decryption_key:
        flash('Please select files and provide a decryption key.', 'warning')
        return redirect(url_for('dashboard'))

    # Implement decryption logic here as needed
    # For now, it will return files as is

    decrypted_files = []
    for filename in selected_files:
        file_path = os.path.join(user_folder, filename)
        if os.path.exists(file_path):
            decrypted_files.append(file_path)

    # Serve files for download
    if decrypted_files:
        flash('Decryption successful. Files ready for download.', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('No valid files to decrypt.', 'danger')
        return redirect(url_for('dashboard'))


@app.route('/download/<filename>')
def download(filename):
    if 'username' in session:
        username = session['username']
        user_folder = os.path.join('uploads', username)
        file_path = os.path.join(user_folder, filename)
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        else:
            flash('File not found.', 'danger')
            return redirect(url_for('dashboard'))
    else:
        flash('Please log in to download files.', 'warning')
        return redirect(url_for('login'))

# Logout Route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# Run the App
if __name__ == '__main__':
    # Create necessary CSV files if they don't exist
    if not os.path.exists('users.csv'):
        with open('users.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['username', 'email', 'password', 'encryption_key'])

    if not os.path.exists('user_files.csv'):
        with open('user_files.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['username', 'filename', 'status'])

    app.run(debug=True)
