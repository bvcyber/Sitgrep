import os
import zipfile
import tarfile
import rarfile
import gzip
import py7zr
import shutil
import hashlib
from pathlib import Path
import time
from utils import messages as msg
from rich.console import Console


SUPPORTED_EXTS = [
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".tar.gz",
    ".rar",
    ".7z",
    ".tar.xz",
    ".bz2",
]
console = Console(color_system="truecolor")

# Choose available extractor for .rar support
if shutil.which("unar"):
    rarfile.UNRAR_TOOL = "unar"
elif shutil.which("7z"):
    rarfile.UNRAR_TOOL = "7z"
elif shutil.which("unrar"):
    rarfile.UNRAR_TOOL = "unrar"
else:
    rarfile.UNRAR_TOOL = None


def is_supported_archive(file_path):
    return any(file_path.endswith(ext) for ext in SUPPORTED_EXTS)


def extract_if_archive(file_path):
    # Skip if not a regular file or not an archive
    if not os.path.isfile(file_path):
        return file_path

    if not is_supported_archive(file_path):
        return file_path

    # Generate a clean, hashed name for the output folder
    basename = os.path.basename(file_path)
    name_hash = hashlib.md5(
        (file_path + time.strftime("%Y%m%d%H%M%S")).encode()
    ).hexdigest()[:6]
    clean_name = basename.replace(".", "_")
    extract_dir = os.path.join(
        os.path.dirname(file_path), f"sitgrep_unzipped_{clean_name}_{name_hash}"
    )

    # Prepare output folder
    try:
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
        if not file_path.endswith(".rar"):
            os.makedirs(extract_dir)
    except PermissionError as pe:
        msg.error(
            f"Permission denied: cannot create or overwrite extraction directory: {extract_dir}",
            False,
        )
        msg.error(f"Details: {pe}", console, False)
        raise
    except Exception as e:
        msg.error(
            f"Failed to prepare extraction directory: {extract_dir}", console, False
        )
        msg.error(f"Details: {e}", console, False)
        raise

    msg.info(f"Extracting archive to: {extract_dir}")

    try:
        # Handle .zip files
        if file_path.endswith(".zip"):
            with zipfile.ZipFile(file_path, "r") as zf:
                zf.extractall(extract_dir)

        # Handle .tar and compressed tar variants
        elif tarfile.is_tarfile(file_path) and any(
            file_path.endswith(ext)
            for ext in [".tar", ".tar.gz", ".tgz", ".gz", ".tar.xz", ".tar.bz2"]
        ):
            with tarfile.open(file_path, "r:*") as tf:
                tf.extractall(extract_dir)

        elif file_path.endswith(".gz"):
            output_filename = Path(file_path).stem
            extract_dir = os.path.join(extract_dir, output_filename)
            with gzip.open(file_path, "rb") as f_in:
                with open(extract_dir, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)

        # Handle .rar files
        elif file_path.endswith(".rar"):
            if not rarfile.UNRAR_TOOL:
                msg.error(
                    "RAR archive detected, but no supported extractor was found.",
                    console,
                    False,
                )
                msg.warn("Please install one of the following to proceed:")
                msg.warn("  • macOS: brew install unar or rar")
                msg.warn("  • Ubuntu/Debian: sudo apt install unar or unrar")
                raise Exception("Missing system extractor for RAR files")

            with rarfile.RarFile(file_path) as rf:
                if rf.needs_password():
                    msg.warn("Skipping password-protected RAR archive.")
                    raise Exception(
                        "RAR archive is password-protected and cannot be extracted."
                    )
                else:
                    os.makedirs(extract_dir)
                    try:
                        rf.extractall(path=extract_dir)
                    except rarfile.BadRarFile as bre:
                        msg.warn(f"RAR archive may be corrupted: {file_path}")
                        msg.warn(f"Details: {bre}")
                        raise

        # Handle .7z files
        elif file_path.endswith(".7z"):
            with py7zr.SevenZipFile(file_path, mode="r") as z:
                z.extractall(path=extract_dir)
        else:
            msg.error("No method of extraction for the given file type", console, False)

        return extract_dir

    # General extraction failure handling
    except Exception as e:
        msg.error(f"Failed to extract archive: {file_path}", console)
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise
