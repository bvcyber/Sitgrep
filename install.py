#!/usr/bin/env python


import os
import sys
import shutil
import subprocess
import getpass
import argparse
from rich_argparse import RichHelpFormatter
from rich.console import Console

console = Console(color_system="truecolor")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from utils import logging as msg


def get_user_home():
    return os.path.expanduser(f"~{getpass.getuser()}")


local_files = f"{get_user_home()}/.sitgrep"


def error(message):
    console.print(f"{msg.get_error(message)}")
    sys.exit(1)


def success(message):
    console.print(f"{msg.get_success(message)}")


def info(message):
    console.print(f"{msg.get_info(message)}")


def warn(message):
    console.print(f"{msg.get_warn(message)}")


def install_error(line_number, e):
    error(f"There was an error while installing at line {line_number}: {e}")


def setup_error(line_number, e):
    error(f"There was an error while setting up at line {line_number}: {e}")
    exit(1)


def get_os():
    if os.name == "nt":
        return "nt"
    elif os.name == "posix":
        return "posix"
    else:
        return "unknown"


def is_user_admin():
    result = True
    if get_os() == "posix":
        if os.geteuid() != 0:
            result = False

    else:
        error("Unsupported operating system detected. Quitting.")
        sys.exit(1)

    return result


def run(*args, **kwargs):
    from subprocess import run
    from sys import stdin

    return run(*args, **kwargs, stdin=stdin, capture_output=True, text=True)


def install(args: argparse.Namespace):

    try:
        info("Installing Opengrep")
        if get_os() != "nt":
            subprocess.run(
                "curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash",
                shell=True,
                check=True,
            )
        else:
            subprocess.run(
                "irm https://raw.githubusercontent.com/opengrep/opengrep/main/install.ps1 | iex",
                shell=True,
                check=True,
            )
        run(["python3", "-m", "pip", "install", "--upgrade", "pip"])

        install = None
        if hasattr(sys, "real_prefix") or sys.base_prefix != sys.prefix:
            # If user is in a venv
            info("Installing Sitgrep for virtual environments...")
            install = run(["python3", "-m", "pip", "install", "-e", "."])
        else:
            # If user is not in a venv
            info("Installing Sitgrep...")
            install = run(["python3", "-m", "pip", "install", "-e", ".", "--user"])

        if "ERROR" in install.stderr:
            error(install.stderr)
        info("Copying files...")
        shutil.copytree(src="src/rules", dst=f"{local_files}/rules", dirs_exist_ok=True)
        shutil.copytree(src="src/web", dst=f"{local_files}/web", dirs_exist_ok=True)
        shutil.copytree("src/tools", f"{local_files}/tools", dirs_exist_ok=True)
        if not os.path.isfile(f"{local_files}/config/sources.json") or args.overwrite:
            if args.overwrite:
                info("Config found, overwriting current config...")
            shutil.copytree(
                src="src/config", dst=f"{local_files}/config", dirs_exist_ok=True
            )
        elif not args.overwrite:
            info("Config found, not overwriting current config...")
            shutil.copy(
                src="src/config/.sources.json",
                dst=f"{local_files}/config/.sources.json",
            )
        else:
            raise Exception

    except Exception as e:
        install_error(sys.exc_info()[-1].tb_lineno, e)

    success("Installation successful")
    print()
    info("Run 'sitgrep sources fetch' to download rules to use locally")

    console.print("\nFor usage details, read README.md or run the following command:\n")
    console.print("sitgrep --help")

    console.print()
    sys.stdout.flush()
    sys.exit(0)


def setup():

    try:
        if os.path.isdir(local_files):
            info("Installation found. Overwriting current installation...")
            preserve = "config"

            for item in os.listdir(local_files):
                item_path = os.path.join(local_files, item)

                if item == preserve:
                    continue

                if os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                else:
                    os.remove(item_path)

        os.makedirs(local_files, exist_ok=True)

    except Exception as e:
        setup_error(sys.exc_info()[-1].tb_lineno, e)


def prechecks():

    try:
        if is_user_admin():
            error(
                "Root user detected. Please run this script as your user, not sudo/root/admin."
            )
            sys.exit(1)

        # Try running the command
        result = subprocess.run(
            ["python3", "-m", "pip", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=RichHelpFormatter)
    parser.add_argument("-w", "--overwrite", action="store_true")
    args = parser.parse_args()
    prechecks()
    setup()
    install(args)
