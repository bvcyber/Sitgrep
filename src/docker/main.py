from flask import Flask, request, render_template, redirect, send_from_directory, send_file, Response, jsonify
import os
import logging
from werkzeug.exceptions import RequestEntityTooLarge
import zipfile
import subprocess
import pty
from io import BytesIO
import shutil
import re

# ANSI color codes mapping to CSS styles
ANSI_TO_HTML = {
    '\033[91m': '<span style="color: red;">',       # RED
    '\033[92m': '<span style="color: green;">',     # GREEN
    '\033[93m': '<span style="color: yellow;">',    # YELLOW
    '\033[96m': '<span style="color: cyan;">',      # CYAN
    '\033[38;5;208m': '<span style="color: orange;">',  # ORANGE (custom color)
    '\033[0m': '</span>'  # RESET (close the span)
}

app = Flask(__name__)

# Set maximum upload size (5 GB)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 * 1024  # 5 GB limit

# Directory to extract ZIP contents
DIRECTORY_PATH = '/target'
os.makedirs(DIRECTORY_PATH, exist_ok=True)  # Create the extracted directory if it doesn't exist

# Configure logging
logging.basicConfig(level=logging.DEBUG)

ansi_escape_pattern = re.compile(r'(\033\[91m|\033\[92m|\033\[93m|\033\[96m|\033\[38;5;208m|\033\[0m)')

# Function to replace ANSI codes with corresponding HTML
def ansi_to_html(text):
    # Function to replace matched ANSI code with its corresponding HTML
    def replace_ansi(match):
        ansi_code = match.group(0)  # Get the matched ANSI code
        return ANSI_TO_HTML.get(ansi_code, '')  # Replace with corresponding HTML

    # Replace ANSI codes in the text
    text_with_html = ansi_escape_pattern.sub(replace_ansi, text)
    
    return text_with_html


@app.route('/')
def upload_form():
    return render_template('upload.html')

@app.route('/scan')
def scan():
    command = ["sitgrep", "local", "-d", DIRECTORY_PATH]
    logging.info("Starting Sitgrep scan")
    
    # Create a pseudo-terminal for the subprocess
    def generate():
        master_fd, slave_fd = pty.openpty()  # Create a pseudo-terminal
        process = subprocess.Popen(command, stdout=slave_fd, stderr=slave_fd, text=True, bufsize=1)
        os.close(slave_fd)  # Close the slave end of the pty in the parent
        results_path = ""

        try:
            buffer = ""  # Buffer for incomplete lines
            while True:
                try:
                    output = os.read(master_fd, 1024).decode()
                except OSError as e:
                    if e.errno == 5:  # Input/output error, meaning the process likely ended
                        break
                if output == '' and process.poll() is not None:
                    break

                # Accumulate the output in the buffer and split on newlines
                buffer += output
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if "Results have been saved to" in line:
                        results_path = line.split(' ')[-1].strip()
                    yield f"data: {ansi_to_html(line)}\n\n"  # Send each line as an SSE message
            # Send the final part of the buffer if it contains any data
            if buffer:
                yield f"data: {ansi_to_html(buffer)}\n\n"
        finally:
            os.close(master_fd)  # Ensure the master file descriptor is closed

        report_folder = '/'.join(results_path.split('/')[:4])
        zip_io = BytesIO()
        logging.info("Compressing results into zip file...")
        with zipfile.ZipFile(zip_io, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Walk the folder and add each file to the zip
            for root, dirs, files in os.walk(report_folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Add file to zip, keeping the directory structure
                    zip_file.write(file_path, os.path.relpath(file_path, report_folder))


        zip_io.seek(0)
        
        yield f"event: download\n"
        yield f"data: /download-zip?folder={report_folder}\n\n"

    return Response(generate(), content_type='text/event-stream')

@app.route('/get-host-directory', methods=['GET'])
def get_host_directory():
    host_directory = os.getenv('HOST_DIRECTORY', '/target')  # Default if not set
    return jsonify({'path': host_directory})

@app.route('/download-zip')
def download_zip():
    # Get the extracted filename from the query parameters
    report_folder = request.args.get('folder')
    filename = report_folder.split('/')[3]
    zip_io = BytesIO()
    
    if report_folder is not None:
        with zipfile.ZipFile(zip_io, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for root, dirs, files in os.walk(report_folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    zip_file.write(file_path, os.path.relpath(file_path, report_folder))

    zip_io.seek(0)
    # Use the filename in the download
    return send_file(zip_io, mimetype='application/zip', as_attachment=True, download_name=f'{os.path.basename(filename)}.zip')

@app.errorhandler(RequestEntityTooLarge)
def handle_file_size_exceeded(error):
    return "File size is too large. Maximum allowed size is 5 GB.", 413

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000)
