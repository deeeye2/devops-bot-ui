from flask import Flask, render_template, request, flash, redirect, url_for, session, Response, jsonify
import sys
import os
import subprocess
import click
from flask_bcrypt import Bcrypt
import xml.etree.ElementTree as ET
from flask import Flask, request, redirect, url_for, flash, render_template
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import psutil
import paramiko
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your-default-secret-key')  # Consistent secret key

active_sessions = {}
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Define the base directory for user data and other configurations
BASE_DIR = os.path.expanduser("~/.etc/devops-bot")

# Define the directory for storing user data and keys
USER_DATA_DIR = os.path.join(BASE_DIR, "users_data")
KEY_FILE = os.path.join(USER_DATA_DIR, "key.key")

# Ensure the directories exist
os.makedirs(USER_DATA_DIR, exist_ok=True)
UPLOAD_FOLDER = '/tmp/screenplay'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Flask-Login User class definition
class User(UserMixin):
    def __init__(self, username):
        self.id = username  # Flask-Login requires the `id` attribute to identify the user.

    @staticmethod
    def get(username):
        """Retrieve user object from XML storage."""
        user_data = load_user_from_xml(username)
        if user_data:
            return User(username)
        return None

# Save user data to XML
def save_user_to_xml(username, password_hash, email, full_name):
    user_dir = os.path.join(USER_DATA_DIR, username)
    os.makedirs(user_dir, exist_ok=True)  # Create user directory if it doesn't exist

    # Create the XML structure
    user_data = ET.Element('user')
    ET.SubElement(user_data, 'username').text = username
    ET.SubElement(user_data, 'password').text = password_hash
    ET.SubElement(user_data, 'email').text = email
    ET.SubElement(user_data, 'full_name').text = full_name

    # Write the XML to a file
    tree = ET.ElementTree(user_data)
    tree.write(os.path.join(user_dir, 'config.xml'))

# Load user data from XML
def load_user_from_xml(username):
    user_dir = os.path.join(USER_DATA_DIR, username)
    config_file = os.path.join(user_dir, 'config.xml')

    if not os.path.exists(config_file):
        return None

    tree = ET.parse(config_file)
    root = tree.getroot()

    password_hash = root.find('password').text
    email = root.find('email').text
    full_name = root.find('full_name').text

    return {
        'username': username,
        'password': password_hash,
        'email': email,
        'full_name': full_name
    }

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if the username already exists
        if os.path.exists(os.path.join(USER_DATA_DIR, username)):
            flash('Username already exists. Please choose another one.', 'danger')
            return redirect(url_for('register'))

        # Hash the password and save user data in XML
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        save_user_to_xml(username, password_hash, email, full_name)

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Load user data from XML
        user_data = load_user_from_xml(username)
        if user_data and bcrypt.check_password_hash(user_data['password'], password):
            user = User(username)  # Create User instance for Flask-Login
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your username and password.', 'danger')

    return render_template('login.html')

# Flask-Login loader to reload the user from the session
@login_manager.user_loader
def load_user(username):
    return User.get(username)

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/file-generator')
@login_required
def file_generator():
    return render_template('file_generator.html')

@app.route('/metrics')
@login_required
def metrics():
    import psutil
    import datetime

    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")

    metrics_data = {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'cpu_user_time': psutil.cpu_times().user,
        'cpu_system_time': psutil.cpu_times().system,
        'cpu_idle_time': psutil.cpu_times().idle,
        'cpu_count': psutil.cpu_count(),
        'memory_percent': psutil.virtual_memory().percent,
        'memory_total': round(psutil.virtual_memory().total / (1024 * 1024 * 1024), 2),
        'memory_used': round(psutil.virtual_memory().used / (1024 * 1024 * 1024), 2),
        'memory_available': round(psutil.virtual_memory().available / (1024 * 1024 * 1024), 2),
        'disk_percent': psutil.disk_usage('/').percent,
        'disk_total': round(psutil.disk_usage('/').total / (1024 * 1024 * 1024), 2),
        'disk_used': round(psutil.disk_usage('/').used / (1024 * 1024 * 1024), 2),
        'disk_free': round(psutil.disk_usage('/').free / (1024 * 1024 * 1024), 2),
        'network_sent': round(psutil.net_io_counters().bytes_sent / (1024 * 1024), 2),
        'network_received': round(psutil.net_io_counters().bytes_recv / (1024 * 1024), 2),
        'network_packets_sent': psutil.net_io_counters().packets_sent,
        'network_packets_received': psutil.net_io_counters().packets_recv,
        'boot_time': boot_time
    }
    return jsonify(metrics_data)

@app.route('/generate-token', methods=['POST'])
@login_required
def generate_token():
    username = current_user.id

    try:
        result = subprocess.run(
            ['python3', '/home/devops-bot/devops_bot/devops_bot/cli.py', '--username', username],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            flash(f"Error: {result.stderr}", 'danger')
        else:
            flash(f"Token: {result.stdout.strip()}", 'success')
    except Exception as e:
        flash(f"Error generating token: {str(e)}", 'danger')

    return redirect(url_for('index'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        if bcrypt.check_password_hash(current_user.password, current_password):
            current_user.update_password(new_password)
            flash('Password updated successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Current password is incorrect.', 'danger')
    return render_template('change_password.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        email = request.form['email']
        full_name = request.form['full_name']
        current_user.update(email=email, full_name=full_name)
        flash('Settings updated successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('settings.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/ssh', methods=['POST'])
def ssh():
    data = request.get_json()

    hostname = data.get('hostname')
    username = data.get('username')
    password = data.get('password')
    command = data.get('command')

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect using username and password
        client.connect(hostname, username=username, password=password)

        # Execute the command sent from the frontend
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()

        if output:
            return jsonify({"output": output}), 200
        elif error:
            return jsonify({"error": error}), 400

    except paramiko.AuthenticationException:
        return jsonify({"error": "Authentication failed, please check your credentials"}), 401
    except paramiko.SSHException as e:
        return jsonify({"error": f"SSH error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"General error: {str(e)}"}), 500
    finally:
        client.close()

    # If no output or error, return a default response
    return jsonify({"error": "No output or error generated"}), 500

@app.route('/close_ssh', methods=['POST'])
def close_ssh():
    data = request.get_json()
    hostname = data.get('hostname')
    username = data.get('username')

    session_id = f"{hostname}_{username}"

    # Close and remove the SSH session
    if session_id in active_sessions:
        client = active_sessions.pop(session_id, None)
        if client:
            client.close()
        return jsonify({"message": "SSH session closed"}), 200
    return jsonify({"error": "No SSH session to close"}), 400
@app.route('/execute', methods=['POST'])
@login_required
def execute():
    if request.method == 'POST':
        yaml_content = request.form['yaml_content']

        # Ensure the directory exists before writing the file
        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        temp_yaml_path = os.path.join(UPLOAD_FOLDER, 'temp_screenplay.yaml')
        with open(temp_yaml_path, 'w') as temp_yaml_file:
            temp_yaml_file.write(yaml_content)

        def generate():
            process = subprocess.Popen(
                ['dob', 'screenplay', temp_yaml_path, '-y'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=os.environ.copy()
            )
            for stdout_line in iter(process.stdout.readline, ""):
                yield f"<div>{stdout_line.strip()}</div>\n"
            process.stdout.close()
            return_code = process.wait()
            if return_code:
                for stderr_line in process.stderr:
                    yield f"<div style='color: red;'>{stderr_line.strip()}</div>\n"
            process.stderr.close()

        return Response(generate(), mimetype='text/html')


@app.route('/execute_command', methods=['POST'])
@login_required
def execute_command():
    command_input = request.form.get('command_input')
    if not command_input:
        return "Command not provided", 400

    try:
        result = subprocess.run(command_input, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return f"<div style='color: red;'>{result.stderr}</div>", 500
        return f"<div>{result.stdout}</div>", 200
    except Exception as e:
        return f"<div style='color: red;'>Error: {str(e)}</div>", 500

@click.group()
def cli():
    pass

@cli.command(name="run-ui", help="Run the UI for the screenplay.")
@click.option('--port', default=4102, help="Port to run the UI on.")
def run_ui(port):
    os.environ["FLASK_APP"] = "app.py"
    click.echo(f"Starting the UI on port {port}...")
    subprocess.run(["flask", "run", "--host=0.0.0.0", f"--port={port}"], env=os.environ)


if __name__ == '__main__':
    cli()
    app.run(host='0.0.0.0', port=4102, debug=True)  # Expose on all interfaces
