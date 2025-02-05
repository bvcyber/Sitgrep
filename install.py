#!/usr/bin/env python


import os
import sys
import shutil
import subprocess
import getpass
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.utils import messages as msg

# ANSI color codes
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[0;33m"
CLEAR = "\033[0m"
ORANGE = "\033[38;5;208m"


def get_user_home():
    return os.path.expanduser(f"~{getpass.getuser()}")


def error(message):
    print(f"{msg.get_error(message)}")
    sys.exit(1)


def success(message):
    print(f"{msg.get_success(message)}")


def info(message):
    print(f"{msg.get_info(message)}")


def warn(message):
    print(f"{msg.get_warn(message)}")


def install_error(line_number, e):
    error(f"There was an error while installing at line {line_number}: {e}")

def setup_error(line_number, e):
    error(f"There was an error while setting up at line {line_number}: {e}")
    exit(1)

def get_os():
    if os.name == 'nt':
       return "nt"
    elif os.name == 'posix':
       return "posix"
    else:
        return "unknown"

def is_user_admin():
    result = True
    if get_os() == 'posix':
        if os.geteuid() != 0:
            result = False

    else:
        error("Unsupported operating system detected. Quitting.")
        sys.exit(1)
    
    return result 

def run(*args, **kwargs):
    from subprocess import run
    from sys import stdin, stderr, stdout

    return run(
        *args,
        **kwargs,
        stdin=stdin,
        capture_output=True,
        text=True
    )


def install():
    
    try:
        run(["python3", "-m", "pip", "install", "--upgrade", "pip"])
        info("Installing Sitgrep...")
        install = run(["python3", "-m", "pip", "install", "--user", "-e", ".", "--break-system-packages"])
        if "ERROR" in install.stderr:
            error(install.stderr)
        local_files = f"{os.path.expanduser(f"~{getpass.getuser()}")}/.sitgrep"
        shutil.copytree("src/rules/", f"{local_files}/rules/", dirs_exist_ok=True)
        shutil.copytree("src/web", f"{local_files}/web", dirs_exist_ok=True)
        
    except Exception as e:
        install_error(sys.exc_info()[-1].tb_lineno, e)

    success("Installation successful")
    print()
    warn("Run 'sitgrep fetch' to download rules to use locally")


    print("\nFor usage details, read README.md or run the following command:\n")
    print("sitgrep -h")

    print()
    sys.stdout.flush()
    sys.exit(0)


def setup():
    
    local_files = f"{get_user_home()}/.sitgrep"

    try:

        if os.path.isdir(local_files):
            info("Installation found. Overwriting current installation...")
            shutil.rmtree(local_files)

        os.makedirs(local_files, exist_ok=True)

    except Exception as e:
        setup_error(sys.exc_info()[-1].tb_lineno, e)

def prechecks():

    try:
        if get_os() == "nt":
            warn("Please use the Docker image when using Sitgrep on Windows.")
            sys.exit(1)

        if is_user_admin():
            error("Root user detected. Please run this script as your user, not sudo/root/admin.")
            sys.exit(1)

        # Try running the command
        result = subprocess.run(
            ["python3", "-m", "pip", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Check if the command was successful
        if result.returncode == 0:
            return True
        else:
            raise FileNotFoundError  # Command ran but failed

    except FileNotFoundError:
        error("The command 'python3 -m pip --version' failed while doing prechecks")
    except Exception as e:
        error(f"An unknown error occured while doing prechecks.\n{e}")

prechecks()
setup()
install()
