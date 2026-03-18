from flask import (
    Flask,
    request,
    render_template,
    redirect,
    send_from_directory,
    send_file,
    Response,
    jsonify,
)
import os
import logging
from werkzeug.exceptions import RequestEntityTooLarge
import zipfile
import subprocess
import pty
from io import BytesIO
import shutil
import urllib.parse
import re

# ANSI color codes mapping to CSS styles
ANSI_TO_HTML = {
    "\033[31m": '<span style="color: red;">',  # RED
    "\033[32m": '<span style="color: green;">',  # GREEN
    "\033[33m": '<span style="color: yellow;">',  # YELLOW
    "\033[36m": '<span style="color: cyan;">',  # CYAN
    "\033[38;5;208m": '<span style="color: orange;">',  # ORANGE (custom color)
    "\033[0m": "</span>",  # RESET (close the span)
    "\033[1m": '<span style="font-weight: bold;">',  # BOLD
}

app = Flask(__name__)

# Set maximum upload size (5 GB)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024 * 1024  # 5 GB limit

# Directory to extract ZIP contents
DIRECTORY_PATH = "/target"
os.makedirs(
    DIRECTORY_PATH, exist_ok=True
)  # Create the extracted directory if it doesn't exist

# Configure logging
logging.basicConfig(level=logging.DEBUG)

ansi_escape_pattern = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")


# Function to replace ANSI codes with corresponding HTML
def ansi_to_html(text):
    # Function to replace matched ANSI code with its corresponding HTML
    def replace_ansi(match):
        ansi_code = match.group(0)  # Get the matched ANSI code
        return ANSI_TO_HTML.get(ansi_code, "")  # Replace with corresponding HTML

    # Replace ANSI codes in the text
    text_with_html = ansi_escape_pattern.sub(replace_ansi, text)

    return text_with_html.replace("\033[?25l", "").replace("\033[?25h", "")


def get_clean_path(url_path):
    decoded = urllib.parse.unquote(url_path)
    ansi_escape = re.compile(r"\x1B\[[0-9;?]*[ -/]*[@-~]")
    clean = ansi_escape.sub("", decoded)

    return urllib.parse.quote(clean)


@app.route("/")
def upload_form():
    return render_template("upload.html")


@app.route("/scan")
def scan():
    command = ["sitgrep", "local", "-d", DIRECTORY_PATH]
    logging.info("Starting Sitgrep scan")

    # Create a pseudo-terminal for the subprocess
    def generate():
        master_fd, slave_fd = pty.openpty()  # Create a pseudo-terminal
        process = subprocess.Popen(
            command, stdout=slave_fd, stderr=slave_fd, text=True, bufsize=1
        )
        os.close(slave_fd)  # Close the slave end of the pty in the parent
        results_path = ""

        try:
            buffer = ""  # Buffer for incomplete lines
            while True:
                try:
                    output = os.read(master_fd, 1024).decode()
                except OSError as e:
                    if (
                        e.errno == 5
                    ):  # Input/output error, meaning the process likely ended
                        break
                if output == "" and process.poll() is not None:
                    break

                # Accumulate the output in the buffer and split on newlines
                buffer += output
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if "sitgrep-report" in line:
                        results_path = line.split(" ")[-1].strip()
                        logging.info("Result path found...")
                        logging.info(line)
                    elif "ERROR" in line:
                        logging.error("Error has occurred during scan")
                        exit(1)
                    yield f"data: {ansi_to_html(line)}\n\n"  # Send each line as an SSE message
            # Send the final part of the buffer if it contains any data
            if buffer:
                yield f"data: {ansi_to_html(buffer)}\n\n"
        finally:
            os.close(master_fd)  # Ensure the master file descriptor is closed
        if results_path == "":
            logging.error("results path returned empty")
            exit(1)
        results_path = get_clean_path(results_path)
        report_folder = "/".join(results_path.split("/")[0:-1])
        logging.info(report_folder)
        zip_io = BytesIO()
        logging.info("Compressing results into zip file...")
        with zipfile.ZipFile(zip_io, "w", zipfile.ZIP_DEFLATED) as zip_file:
            # Walk the folder and add each file to the zip
            for root, dirs, files in os.walk(report_folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    zip_file.write(file_path, os.path.relpath(file_path, report_folder))
                    logging.info(os.path.relpath(file_path, report_folder))

        zip_io.seek(0)

        yield f"event: download\n"
        yield f"data: /download-zip?folder={report_folder}\n\n"

    return Response(generate(), content_type="text/event-stream")


@app.route("/get-host-directory", methods=["GET"])
def get_host_directory():
    host_directory = os.getenv("HOST_DIRECTORY", "/target")  # Default if not set
    return jsonify({"path": host_directory})


@app.route("/download-zip")
def download_zip():
    # Get the extracted filename from the query parameters
    report_folder = request.args.get("folder")
    zip_io = BytesIO()
    print(report_folder)
    if report_folder is not None:
        filename = report_folder.split("/")[-1]
        with zipfile.ZipFile(zip_io, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for root, dirs, files in os.walk(report_folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    zip_file.write(file_path, os.path.relpath(file_path, report_folder))

    zip_io.seek(0)
    # Use the filename in the download
    return send_file(
        zip_io,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"{os.path.basename(filename)}.zip",
    )


@app.errorhandler(RequestEntityTooLarge)
def handle_file_size_exceeded(error):
    return "File size is too large. Maximum allowed size is 5 GB.", 413


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
