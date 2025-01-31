import subprocess
import webbrowser
import json
import os
from urllib.parse import urlparse
import time
import re
import sys
import argparse
import shutil
from utils import messages as msg
from utils.rulefetcher import RuleFetcher
from utils.progressbar import ProgressBar
from git import (
    Repo,
)
from git.exc import GitCommandError

VERSION = "3.6.8"
TIMESTR = time.strftime("%Y%m%d%H%M%S")
START_DIR = os.getcwd()
INSTALL_DIR = f"{os.path.expanduser('~')}/.sitgrep"
LOCAL_MODE = False
NO_OPEN = False
VERBOSE_LEVEL = 0
CONTEXT_LINE_COUNT = 5


class BadScanException(Exception):
    def __init__(self):
        super().__init__()


def scan(dir):
    cmd = []
    cmd_string = ""

    try:
        process = subprocess.Popen(
            ["semgrep", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate()
    except:
        msg.error("Failed to invoke Semgrep. Exiting.")
        sys.exit(1)

    try:
        cmd = [
            "semgrep",
            "scan",
            "--json",
            "--exclude=sitgrep-report*",
            "--exclude=sitgrep-config.json",
            "--exclude=semgrep-output.json",
            "--exclude=tst",
            "--exclude=test",
            "--exclude=tests",
            "--no-git-ignore",
            f"-o semgrep-scan-{TIMESTR}"
        ]

        if VERBOSE_LEVEL > 2:
            cmd.extend(["--debug"])
        elif VERBOSE_LEVEL == 2:
            cmd.extend(["--verbose"])

        if LOCAL_MODE:
            cmd.extend(["--metrics=off", "--config", f"{INSTALL_DIR}/rules/", dir])
        else:
            cmd.extend(
                ["--config", "auto", "--config", f"{INSTALL_DIR}/rules/local/", dir]
            )

        cmd_string = " ".join(cmd)

        output = {}

        with subprocess.Popen(
            cmd_string,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            encoding="utf-8",
            universal_newlines=True,
            shell=True,
        ) as process:
            isScanning = False
            hasPrintedMessages = False
            msg.info("Semgrep is loading rules...")

            while True:
                line = process.stdout.readline()
                if line == "" and process.poll() is not None:
                    break
                if line.strip() != "":
                    isScanning = True

                if isScanning:
                    if not hasPrintedMessages:
                        msg.info("Scanning... this may take a few minutes...")
                        if VERBOSE_LEVEL > 0:
                            msg.info(
                                f"------------- Semgrep output start -------------"
                            )
                        hasPrintedMessages = True

                    if VERBOSE_LEVEL > 0:
                        if '{"errors' not in line:
                            print(line.strip(), flush=True)

                if (
                    "scanning 0 files" in line.lower()
                    or "nothing to scan" in line.lower()
                ):
                    raise BadScanException

        process.wait()
        if os.path.isfile(f"semgrep-scan-{TIMESTR}"):
            with open(f"semgrep-scan-{TIMESTR}") as output:
                try:
                    output = json.loads(str(output.read()))
                    os.remove(f"semgrep-scan-{TIMESTR}")  
                except Exception as e: 
                    msg.error(e)
                    sys.exit(1)
        else:
            raise BadScanException
        save_raw_semgrep_output(output)
        if VERBOSE_LEVEL > 0:
            msg.info("-------------- Semgrep output end --------------")
            msg.info(f"Semgrep command used: {cmd_string}")
            msg.info(
                f"The raw Semgrep JSON output was saved to {os.getcwd()+'/semgrep-output.json'}"
            )
        msg.info("Scanning complete")

        return output

    except BadScanException as bse:
        print()
        if VERBOSE_LEVEL > 0:
            msg.info("-------------- Semgrep output end --------------")
        msg.error(
            "Semgrep attempted to scan 0 files. Check if the specified directory is listed in a .gitignore file for the project being scanned. The specified directory or the results may also be empty."
        )
        msg.info(f"Semgrep command: {cmd_string}")
        try:
            os.remove(f"semgrep-scan-{TIMESTR}")  
        except:
            pass
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print()
        if VERBOSE_LEVEL > 0:
            msg.info("-------------- Semgrep output end --------------")

        msg.error(f"Semgrep returned with errors: {e.stdout}")
        msg.info(f"Semgrep command: {cmd_string}")
        try:
            os.remove(f"semgrep-scan-{TIMESTR}")  
        except:
            pass
        sys.exit(1)

    except Exception as e:
        print()
        if VERBOSE_LEVEL > 0:
            msg.info("-------------- Semgrep output end --------------")
            msg.info(f"Semgrep command: {cmd_string}")
        msg.error(f"An error occurred: {str(e)}")
        try:
            os.remove(f"semgrep-scan-{TIMESTR}")  
        except:
            pass
        sys.exit(1)


def getPackageName(file_path, packages):
    for package_obj in packages:
        for file in file_path.split("/"):
            if file.lower() == package_obj["project"].lower():
                return file
    return ""


def process_json(results, dir, packages) -> dict:

    json_results = {"sitgrepVersion": f"Sitgrep v{VERSION}", "results": []}

    try:

        if len(results) == 0:
            return results

        groupIndex = 0
        for index, result in enumerate(results):

            file = result["path"]
            finding_text = result["extra"]["lines"]
            file_path = os.path.join(START_DIR, file)
            package_name = getPackageName(file, packages)

            if "cwe" not in result["extra"]["metadata"]:
                result["extra"]["metadata"]["cwe"] = "N/A"
            if "confidence" not in result["extra"]["metadata"]:
                result["extra"]["metadata"]["confidence"] = "N/A"
            if "impact" not in result["extra"]["metadata"]:
                result["extra"]["metadata"]["impact"] = "N/A"
            if "likelihood" not in result["extra"]["metadata"]:
                result["extra"]["metadata"]["likelihood"] = "N/A"
            if "owasp" not in result["extra"]["metadata"]:
                result["extra"]["metadata"]["owasp"] = "N/A"

            with open(file_path, "r") as f:
                file_text = f.read()

                start_line = result["start"]["line"]
                end_line = result["end"]["line"]
                lines = file_text.splitlines()
                context = finding_text

                context = lines[
                    max(start_line - (CONTEXT_LINE_COUNT + 1), 0) : end_line
                    + CONTEXT_LINE_COUNT
                ]

                context = "\n".join(context)

                rule_id = result["check_id"].split(".")
                rule_id = rule_id[-1]

                rule_index = get_rule_index(json_results["results"], rule_id)

                new_file_path = f"{file.replace(os.path.abspath(dir), '')}"
                if new_file_path.startswith("/"):
                    new_file_path = new_file_path[1:]

                if rule_index == -1:
                    json_results["results"].append(
                        {
                            "id": str(groupIndex),
                            "rule_id": rule_id,
                            "cwe": result["extra"]["metadata"]["cwe"],
                            "description": result["extra"]["message"],
                            "impact": result["extra"]["metadata"]["impact"],
                            "likelihood": result["extra"]["metadata"]["likelihood"],
                            "owasp": result["extra"]["metadata"]["owasp"],
                            "confidence": result["extra"]["metadata"]["confidence"],
                            "findings": [
                                {
                                    "id": f"{groupIndex}::{0}",
                                    "file": new_file_path,
                                    "package": package_name,
                                    "context": context,
                                    "end": result["end"]["line"],
                                    "start": result["start"]["line"],
                                    "file-size": len(lines),
                                    "fullFile": file,
                                }
                            ],
                        }
                    )
                    groupIndex += 1
                else:
                    json_results["results"][rule_index]["findings"].append(
                        {
                            "id": f'{json_results["results"][rule_index]["id"]}::{len(json_results["results"][rule_index]["findings"])}',
                            "file": new_file_path,
                            "package": package_name,
                            "context": context,
                            "end": result["end"]["line"],
                            "start": result["start"]["line"],
                            "file-size": len(lines),
                            "fullFile": file,
                        }
                    )

        return json_results
    except KeyError as k:
        msg.error(f"The following key could not be found while parsing JSON: {k}")
        sys.exit(1)
    except Exception as e:
        msg.error(f"Error parsing JSON: {e}")
        sys.exit(1)


def get_rule_index(results: list, rule_id):
    for index, result in enumerate(results):
        if "rule_id" in result and result["rule_id"] == rule_id:
            return index
    return -1


def count_findings(results):

    count = 0

    for rule in results["results"]:
        count += len(rule["findings"])

    return count


def save_results(scan_results: dict, output_file, dir="", packages=[]):

    try:
        processed_results: dict = process_json(scan_results["results"], dir, packages)
        processed_results["packages"] = packages
        processed_results["contextLength"] = CONTEXT_LINE_COUNT

        if len(processed_results) > 0:
            try:
                goto_output_dir()

                base = open(f"{INSTALL_DIR}/web/templates/template.html", "r").read()

                output_file_old = output_file
                counter = 0
                while os.path.isfile(f"{output_file}.html") and counter < 100:
                    output_file = output_file_old + f"_{counter}"

                with open(f"{output_file}.html", "a") as html_file:
                    html_file.write(base)
                os.mkdir("static")
                shutil.copytree(f"{INSTALL_DIR}/web/static/js", f"static/js")
                shutil.copytree(f"{INSTALL_DIR}/web/static/css", f"static/css")
                shutil.copytree(f"{INSTALL_DIR}/web/static/img", f"static/img")

                if not os.path.isdir("results"):
                    os.mkdir("results")

                with open(f"results/results.js", "a") as js_file:
                    js_file.write(
                        f"const sitgrep_results = {json.dumps(processed_results)}"
                    )

                output_file_location = os.path.abspath("{}.html".format(output_file))
                msg.info(
                    f'Scan results: {count_findings(processed_results)} findings after scanning {len(scan_results["paths"]["scanned"])} files'
                )
                msg.success(f"Results have been saved to {output_file_location}")

                if not NO_OPEN:

                    if os.environ.get("WSL_DISTRO_NAME", "none") == "none":
                        webbrowser.open_new_tab(f"file://{output_file_location}")
                    else:
                        os.chdir(f'{"/".join(output_file_location.split("/")[:-1])}')
                        webbrowser.open_new_tab(f"{output_file}.html")
            except FileExistsError as e:
                msg.error(f"The file already exists: {e}")
                sys.exit(-1)
            except Exception as e:
                msg.error(f"There was an error saving the file: {e}")
                sys.exit(-1)
        else:
            msg.success("Congrats, there were no findings.")
    except Exception as e:
        msg.error(f"There was an error saving the output: {e}")
        # traceback.print_exc()
        sys.exit(-1)


def goto_output_dir():
    os.chdir(START_DIR)
    if not os.path.isdir("sitgrep-report"):
        os.mkdir("sitgrep-report")
    os.chdir("sitgrep-report")

    if not os.path.isdir(f"sitgrep-{TIMESTR}"):
        os.mkdir(f"sitgrep-{TIMESTR}")
    os.chdir(f"sitgrep-{TIMESTR}")


def save_raw_semgrep_output(results):
    goto_output_dir()
    with open("semgrep-output.json", "w") as output:
        json.dump(results, output, indent=4)


def parse_github_url(url):

    parsed_url = urlparse(url)
    path_segments = parsed_url.path.lstrip("/").split("/")

    if "/blob/" in parsed_url.path:

        blob_index = path_segments.index("blob")
        group_path = path_segments[: blob_index - 1]
        project = path_segments[blob_index - 1]
        branch_and_file = parsed_url.path.split("/blob/")[1]
        branch, file_path = branch_and_file.split("/", 1)
        user = group_path[0]

        return {
            "path": "/".join(group_path),
            "project": project,
            "user": user,
            "branch": branch,
            "site": "github",
        }

    elif "/tree/" in parsed_url.path:
        user = path_segments[0]
        tree_index = path_segments.index("tree")
        project = path_segments[tree_index - 1]
        group_path = path_segments[: tree_index - 1]
        branch = parsed_url.path.split("/tree/")[1]

        return {
            "path": "/".join(group_path),
            "project": project,
            "user": user,
            "branch": branch,
            "site": "github",
        }

    else:
        try:
            user = path_segments[0]
            branch = ""
            if path_segments[-1] == "":
                del path_segments[-1]
            project = path_segments[-1]
            group_path = path_segments[:-1]

            return {
                "path": "/".join(group_path),
                "project": project,
                "user": user,
                "branch": branch,
                "site": "github",
            }
        except:
            return None


def parse_gitlab_url(url):

    parsed_url = urlparse(url)
    path_segments = parsed_url.path.lstrip("/").split("/")

    if "/-/blob/" in parsed_url.path:

        blob_index = path_segments.index("-")
        group_path = path_segments[: blob_index - 1]
        project = path_segments[blob_index - 1]
        branch_and_file = parsed_url.path.split("/-/blob/")[1]
        branch, file_path = branch_and_file.split("/", 1)
        user = group_path[0]

        return {
            "path": "/".join(group_path),
            "project": project,
            "user": user,
            "branch": branch,
            "site": "gitlab",
        }

    elif "/-/tree" in parsed_url.path:
        user = path_segments[0]
        project = path_segments[-4]
        tree_index = path_segments.index("-")
        group_path = path_segments[: tree_index - 1]
        branch = parsed_url.path.split("/-/tree/")[1]

        return {
            "path": "/".join(group_path),
            "project": project,
            "user": user,
            "branch": branch,
            "site": "gitlab",
        }

    else:
        try:
            user = path_segments[0]
            branch = "main"
            if path_segments[-1] == "":
                del path_segments[-1]
            project = path_segments[-1]
            group_path = path_segments[:-1]

            return {
                "path": "/".join(group_path),
                "project": project,
                "user": user,
                "branch": branch,
                "site": "gitlab",
            }
        except:
            return None


def clone_and_make_config(failed_packages, package_details, progress_bar):
    project_name = package_details["project"]
    branch = (
        package_details["branch"].strip()
        if package_details["branch"].strip() != ""
        else None
    )

    def handle_failed_package(failed_packages, project_name, error):
        failed_packages.append({"package": f"{project_name}", "error": error})

    try:
        if package_details["site"] == "github":
            if branch == "main":
                branch = ""
            Repo.clone_from(
                url=f'https://github.com/{package_details["path"]}/{project_name}.git',
                to_path=f"{os.getcwd()}/{project_name}",
                multi_options=["--single-branch"],
                branch=branch,
                progress=progress_bar,
                depth=1,
                jobs=4,
            )
        elif package_details["site"] == "gitlab":
            if branch == "main":
                branch = ""
            Repo.clone_from(
                url=f'https://gitlab.com/{package_details["path"]}/{project_name}.git',
                to_path=f"{os.getcwd()}/{project_name}",
                multi_options=["--single-branch"],
                branch=branch,
                progress=progress_bar,
                depth=1,
                jobs=4,
            )

        os.chdir(project_name)
        with open("sitgrep-config.json", "w") as config_file:
            json.dump(package_details, config_file)

        os.chdir("../")

    except GitCommandError as e:
        #msg.error(f"The repository wasn't found, you do not have access, or another error occurred: {e}")
        handle_failed_package(failed_packages, project_name, f"The repository wasn't found, you do not have access, or another error occurred. {e}")
    except Exception as e:
        #msg.error(f"Error while downloading package: {e}")
        handle_failed_package(failed_packages, project_name, f"Error while downloading package - {e}")


def download_packages(packages: list):
    print()

    failed_packages = []

    if os.path.isdir("Sitgrep_Packages"):
        shutil.rmtree("Sitgrep_Packages")

    os.mkdir("Sitgrep_Packages")
    os.chdir("Sitgrep_Packages")

    
    for package in packages:
        progress_bar = ProgressBar(package["project"], hide=False)

        clone_and_make_config(failed_packages, package, progress_bar)

    if len(failed_packages) == len(packages):
        print()
        msg.error("All packages failed to download.")

        for failed_package in failed_packages:
            msg.error(f'Package {failed_package["project"]}: {failed_package["error"]}')

        sys.exit(1)

    else:
        if len(failed_packages) > 0:
            print()
            msg.error(f"The following packages failed to be downloaded:\n")
            for failed_package in failed_packages:
                msg.error(
                    f'Package {failed_package["project"]}: {failed_package["error"]}'
                )
            print()
        else:
            msg.success(
                f"Successfully downloaded {len(packages)-len(failed_packages)} package(s)\n"
            )

def is_valid_package_name(package: str):
    pattern = r"^[a-zA-Z0-9-_/.]+(::[a-zA-Z0-9-_/.]+)?$"
    return bool(re.match(pattern, package.strip()))


def split_packages(packages: list, mode: str):
    split_packages = []
    for package in packages:
        if "https://" in package or "http://" in package:
            if "github.com" in package and mode == "github":

                parsed_github_url = parse_github_url(package)

                if not parsed_github_url or parsed_github_url is None:
                    msg.error(f"Unable to parse Github URL: {package}")

                split_packages.append(
                    {
                        "path": parsed_github_url["path"], # type: ignore
                        "project": parsed_github_url["project"], # type: ignore
                        "branch": parsed_github_url["branch"], # type: ignore
                        "user": parsed_github_url["user"], # type: ignore
                        "site": "github",
                    }
                )

            elif "gitlab.com" in package and mode == "gitlab":

                parsed_gitlab_url = parse_gitlab_url(package)

                if not parsed_gitlab_url or parsed_gitlab_url is None:
                    msg.error(f"Unable to parse Github URL: {package}")

                split_packages.append(
                    {
                        "path": parsed_gitlab_url["path"], # type: ignore
                        "project": parsed_gitlab_url["project"], # type: ignore
                        "branch": parsed_gitlab_url["branch"], # type: ignore
                        "user": parsed_gitlab_url["user"], # type: ignore
                        "site": "gitlab",
                    }
                )
            else:
                msg.error(f"Could not parse URL. Only Github and Gitlab links are currently supported.")
                msg.info(
                    f"Please report this so this usecase can be added."
                )
        else:
            msg.error(f"Unable to parse package: {package}")

    return split_packages


def strip_package_names(packages):
    return list(filter(lambda item: item != "", packages))


def get_package_list(packages):
    package_list = []
    if isinstance(packages, list):
        try:
            if os.path.isfile(packages[0]) or packages[0].endswith(".txt"):
                with open(packages[0], "r") as file:
                    package_list = file.read().split("\n")
            else:
                packages = ",".join(packages)
                package_list = packages.split(",")
        except Exception as e:
            msg.error(f"There was an error parsing the package list: {e}")
            sys.exit(1)

    else:
        msg.error(
            f"Unsupported type: Expected a text file or a list of packages, not {type(packages)}"
        )
        sys.exit(1)

    return package_list


def getFolders(dir):
    directory_items = os.listdir(dir)
    directories = [
        item
        for item in directory_items
        if os.path.isdir(os.path.join(dir, item)) and "sitgrep" not in item.lower()
    ]
    return directories


def get_packages_from_dir(dir):
    folders = getFolders(dir)
    packages = []
    os.chdir(dir)

    foundConfig = False

    if os.path.isfile("sitgrep-config.json"):
        config = json.loads(open("sitgrep-config.json", "r").read())
        packages.append(config)
        foundConfig = True

    for folder in folders:
        os.chdir(folder)
        if not foundConfig and os.path.isfile("sitgrep-config.json"):
            config = json.loads(open("sitgrep-config.json", "r").read())
            packages.append(config)
        elif not foundConfig:
            packages.append(
                {
                    "path": dir,
                    "project": folder,
                    "branch": "",
                    "site": "unknown",
                    "user": None,
                }
            )
        os.chdir("../")
    os.chdir("../")
    return packages


def open_dir_in_vscode(dir):

    try:
        if os.path.isdir(dir):
            subprocess.run(["code", "--new-window", dir])
        else:
            raise Exception
    except:
        folder_uri = urlparse(dir)
        vscode_link = f"vscode://file/{folder_uri.path}"
        webbrowser.open(vscode_link)


def print_banner(directory, output_file):
    banner_len = min(os.get_terminal_size().columns, 80)

    print("-" * banner_len)
    print(
        r"""
    ┌─────────────────────┐
    │       Sitgrep       │
    │                     │
    │  Powered by Semgrep │  
    └─────────────────────┘  
"""
    )
    print("Context lines:", CONTEXT_LINE_COUNT)
    print("Directory to scan:", directory)
    print("Output file:", output_file)
    print("Version:", str(VERSION))
    print("-" * banner_len)


def start_scan(directory, output_file, packages, args, ALLOW_DOWNLOAD):

    if LOCAL_MODE and len(packages) > 0 and ALLOW_DOWNLOAD:
        download_packages(packages)
        if args.no_scan:
            sys.exit(1)
    elif len(packages) > 0 and ALLOW_DOWNLOAD:
        download_packages(packages)

    scan_results = scan(directory)

    try:
        if "results" in scan_results and len(scan_results["results"]) > 0:
            save_results(scan_results, output_file, directory, packages)
            if not hasattr(args, "github") and not hasattr(args, "gitlab") and hasattr(args, "vscode"):
                open_dir_in_vscode(dir=directory)
        elif (
            "results" in scan_results
            and "errors" in scan_results
            and len(scan_results["errors"]) > 0
        ):
            valid_errors = []
            for error in scan_results["errors"]:
                if (
                    "missing plugin" not in str(error["type"]).casefold()
                    and "syntax error" not in str(error["message"]).casefold()
                ):
                    valid_errors.append(error)
            if len(valid_errors) > 0:
                msg.error("Semgrep encountered errors and returned no results:")
                msg.error(valid_errors)
            else:
                msg.success("Congrats, there were no findings.")
        else:
            msg.error(
                "There was an error with Semgrep and the results returned null. Please report this issue."
            )
    except Exception as e:
        msg.error(f"There was an error: {e}")


def main(args):
    directory = os.path.abspath(args.directory)
    global CONTEXT_LINE_COUNT
    CONTEXT_LINE_COUNT = args.context

    global VERBOSE_LEVEL
    VERBOSE_LEVEL = args.verbose

    global LOCAL_MODE
    LOCAL_MODE = False

    global NO_OPEN
    NO_OPEN = args.no_auto_open

    ALLOW_DOWNLOAD = False

    packages = []
    if args.output == "" or args.output == None:
        output_file = f"sitgrep-{TIMESTR}"
    else:
        output_file = f"sitgrep-{args.output}"

    if hasattr(args, "subcommands") and args.subcommands == "fetch":
        RuleFetcher().run()
        sys.exit(0)

    if hasattr(args, "json_input") and args.json_input:
        if args.subcommands == "local":
            LOCAL_MODE = True
        try:
            expanded_filepath = os.path.expanduser(args.json_input)
            if os.path.exists(expanded_filepath):
                file = open(expanded_filepath, "r").read()
                semgrep_json = json.loads(file)
                packages = get_packages_from_dir(directory)
                save_results(
                    scan_results=semgrep_json,
                    output_file=output_file,
                    packages=packages,
                    dir=directory,
                )
                sys.exit(0)
            else:
                msg.error(
                    f"The JSON could not be found at the given path: {expanded_filepath}"
                )
        except Exception as e:
            msg.error(f"There was an error loading the JSON file: {e}")
            sys.exit(1)
    elif args.subcommands == "local":
        LOCAL_MODE = True
    try:
        if not hasattr(args, "github") and not hasattr(args, "github"):
            packages = get_packages_from_dir(directory)
        elif (
            hasattr(args, "github")
            or hasattr(args, "gitlab")
        ):
            ALLOW_DOWNLOAD = True

            github_packages: list = []
            gitlab_packages: list = []

            if isinstance(args.github, list) and len(args.github) > 0:
                github_packages = get_package_list(args.github)
                github_packages = strip_package_names(github_packages)
                github_packages = split_packages(github_packages, mode="github")
                directory = (
                    os.path.join(directory, "Sitgrep_Packages")
                    if not ("Sitgrep_Packages" in directory)
                    else directory
                )
            if isinstance(args.gitlab, list) and len(args.gitlab) > 0:
                gitlab_packages = get_package_list(args.gitlab)
                gitlab_packages = strip_package_names(gitlab_packages)
                gitlab_packages = split_packages(gitlab_packages, mode="gitlab")
                directory = (
                    os.path.join(directory, "Sitgrep_Packages")
                    if not ("Sitgrep_Packages" in directory)
                    else directory
                )

            packages = github_packages + gitlab_packages

        else:
            directory = os.path.abspath(directory)
            if not os.path.isdir(directory):
                raise (FileNotFoundError)
    except FileNotFoundError:
        msg.error(f"The directory specified could not be found: {directory}")
        sys.exit(1)
    except Exception as e:
        if hasattr(args, "github") or hasattr(args, "gitlab"):
            msg.error(f"There was an error gathering package data: {e}")
        else:
            msg.error(
                f"There was an error parsing the directory of the package: {e}"
            )
        sys.exit(1)

    except FileNotFoundError:
        msg.error("The directory specified could not be found")
        sys.exit(1)
    except Exception as e:
        msg.error(f"There was an error parsing the directory of the package: {e}")
        sys.exit(1)

    print_banner(directory=directory, output_file=output_file)
    start_scan(directory, output_file, packages, args, ALLOW_DOWNLOAD)


def cli():
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest="subcommands")

    local_parser = subparsers.add_parser(
        "local",
        help="Use local rules instead of official Semgrep rules. Run 'sitgrep local -h' for more info.",
    )

    fetch_parser = subparsers.add_parser(
        "fetch",
        help="Fetch the latest ruleset.",
    )

    local_parser.add_argument(
        "-d",
        "--directory",
        default=os.getcwd(),
        type=str,
        help="The directory to scan (default=CWD)",
    )
    local_parser.add_argument(
        "-o",
        "--output",
        default="",
        type=str,
        help="The output file name",
    )
    local_parser.add_argument(
        "-c",
        "--context",
        default=5,
        type=int,
        help="The amount of context lines above and below to save (default=5)",
    )
    local_parser.add_argument(
        "-N",
        "--no-scan",
        action="store_true",
        help="Only download the packages, do not scan them. (default=False)",
    )
    local_parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity level (default 0, max of 3)",
    )
    local_parser.add_argument(
        "-j",
        "--json-input",
        type=str,
        required=False,
        help="Load a Semgrep JSON output file",
    )
    local_parser.add_argument(
        "-n",
        "--no-auto-open",
        action="store_true",
        required=False,
        help="Disable auto-opening the results in the browser",
    )
    local_parser.add_argument(
        "-gh",
        "--github",
        required=False,
        nargs="+",
        help="Specify Github packages in a text file to download. Accepts Github links.",
    )
    local_parser.add_argument(
        "-gl",
        "--gitlab",
        required=False,
        nargs="+",
        help="Specify Gitlab packages in a text file to download. Accepts Gitlab links.",
    )

    local_parser.add_argument(
        "-vs", "--vscode", action="store_true", help="Open the folder in VSCode"
    )

    parser.add_argument(
        "-c",
        "--context",
        default=5,
        type=int,
        help="The amount of context lines above and below to save (default=5)",
    )
    parser.add_argument(
        "-d",
        "--directory",
        default=os.getcwd(),
        type=str,
        help="The directory to scan (default=CWD)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="",
        type=str,
        help="The output file name",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=str(VERSION),
        help="Print Sitgrep's version",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity level (default 0, max of 3)",
    )
    parser.add_argument(
        "-j",
        "--json-input",
        type=str,
        required=False,
        help="Load a Semgrep JSON output file",
    )
    parser.add_argument(
        "-n",
        "--no-auto-open",
        action="store_true",
        required=False,
        help="Disable auto-opening the results in the browser",
    )
    parser.add_argument(
        "-gh",
        "--github",
        required=False,
        nargs="+",
        help="Specify Github packages in a text file to download. Accepts Github links.",
    )
    parser.add_argument(
        "-gl",
        "--gitlab",
        required=False,
        nargs="+",
        help="Specify Gitlab packages in a text file to download. Accepts Gitlab links.",
    )
    parser.add_argument(
        "-vs", "--vscode", action="store_true", help="Open the folder in VSCode"
    )

    args = parser.parse_args()
    try:
        main(args)
    except KeyboardInterrupt:
        print("", end="\r")
        msg.warn("Detected keyboard interrupt. Exiting...")
    except MemoryError:
        msg.error(
            "Ran out of memory. Please report this package for further investigation."
        )
    except Exception as e:
        msg.error(f"An unknown exception occured: {e}")
