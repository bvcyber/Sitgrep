import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
import ast
import rs_chardet
from git import Repo
from git.exc import GitCommandError
from langchain.messages import AIMessage, HumanMessage, ToolMessage
from pydantic import BaseModel
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
)
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.text import Text
from rich.traceback import install
from rich_argparse import RichHelpFormatter

from agent import agent, model
from agent.agent import SitgrepAgent
from agent.agents.types import AgentType
from utils import logging as log
from utils.archive_handler import extract_if_archive
from utils.progressbar import ProgressBar
from utils.source_handler import SourceHandler

install(show_locals=True)
console = Console(color_system="truecolor")

VERSION = "3.8.0"
TIMESTR = time.strftime("%Y%m%d%H%M%S")
START_DIR = os.getcwd()
INSTALL_DIR = f"{os.path.expanduser('~')}/.sitgrep"
LOCAL_MODE = False
NO_OPEN = False
VERBOSE_LEVEL = 0
CONTEXT_LINE_COUNT = 5
MODES = ["GENERAL", "MOBILE"]
PROTOCOLS = ["SSH", "HTTPS"]
AGENT_ENABLED = False


class BadScanException(Exception):
    def __init__(self):
        super().__init__()


def check_path(filename: str):
    file_path = Path(filename)
    if file_path.exists() and (file_path.is_file() or file_path.is_dir()):
        return
    else:
        raise FileNotFoundError


def validate_mode(value: str) -> list:
    choices = value.split(",")
    for choice in choices:
        if str(choice).upper() not in MODES:
            raise argparse.ArgumentTypeError(
                f"Invalid choice: {value}. Choose from {MODES}"
            )
    return choices


def detect_encoding(file_path: str):
    with open(file_path, "rb") as file:
        raw_data = file.read(10000)
    result = rs_chardet.detect_rs_enc_name(raw_data)
    return result


def extract_tool_calls(msg, agent: AgentType):
    messages = msg["messages"]
    tool_calls = {agent.value: []}

    for msg in messages:
        if isinstance(msg, AIMessage) and len(msg.tool_calls) > 0:
            call = {}
            call["name"] = msg.tool_calls[0]["name"]
            call["args"] = msg.tool_calls[0]["args"]
            tool_calls[agent.value].append(call)

    if VERBOSE_LEVEL > 2:
        log.debug(tool_calls)

    return tool_calls


def extract_tools_invocation(response_dict, tools):
    command_str = response_dict.get("command", "")
    command_str = " ".join(command_str.split())

    if not command_str:
        return None

    # parse: grep_search(file_path="...", pattern="...")
    match = re.match(r"(\w+)\((.*)\)$", command_str.strip())
    if not match:
        return None

    tool_name = match.group(1)
    args_str = match.group(2)

    # parse keyword args
    try:
        # wrap in dict() call so ast can parse it
        node = ast.parse(f"f({args_str})", mode="eval")
        call = node.body
        kwargs = {}
        for kw in call.keywords:  # type: ignore
            try:
                kwargs[kw.arg] = ast.literal_eval(kw.value)
            except Exception:
                # fallback if not a literal
                kwargs[kw.arg] = ast.unparse(kw.value)

        kwargs_escaped = {
            k: v.replace('"', '\\"') if isinstance(v, str) else v
            for k, v in kwargs.items()
        }

    except (ValueError, SyntaxError) as e:
        raise ValueError(f"Failed to parse tool args: {args_str}") from e

    return tool_name, kwargs_escaped


def get_ai_message(output: Any, agent: AgentType):
    if agent == AgentType.JUDGE:
        content = output.model_dump()
        if VERBOSE_LEVEL > 1:
            log.debug(content)
        return content
    else:
        messages = output["messages"]
        for msg in messages:
            if isinstance(msg, AIMessage) and str(msg.content).strip():
                if VERBOSE_LEVEL > 1:
                    log.debug(json.loads(str(msg.content)))
                return json.loads(str(msg.content))

        log.warn("Got empty response from agent...")
        return json.loads("{}")


def ensure_environment_set(env_name: str):
    env_val = os.environ.get(env_name)
    if not env_val:
        log.error(f"{env_name} is not set. Please set {env_name}", console, False)
        return False
    return True


def ensure_program_installed(tool_name: str):
    tool_cmd = shutil.which(tool_name)
    if not tool_cmd:
        log.error(
            f"{tool_name} is not installed. Please install {tool_name}", console, False
        )
        return False
    return True


# Modify this method slightly to add supoort for mobil apk
# cfr can be switched to jadx later
def decompile_jar(jar_file_path: str, output_dir: str):
    jd_path = os.path.join(INSTALL_DIR, "tools", "cfr-0.152.jar")
    log.info(f"Jar File Path: {jar_file_path}")
    log.info(f"Java Decompiler Path: {jd_path}")
    cfr_cmd = [
        "java",
        "-jar",
        jd_path,
        jar_file_path,
        "--silent",
        "true",
        "--outputdir",
        output_dir,
    ]
    log.info("Decompiling...")

    try:
        process = subprocess.Popen(
            cfr_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = process.communicate()
        if stdout:
            log.info(f"{stdout}")
        if stderr:
            if "Unable to access jarfile" in stderr:
                raise FileNotFoundError
            else:
                log.warn(f"{stderr}")
        log.info(f"Successfully decompiled {jar_file_path} to {output_dir}")
    except FileNotFoundError:
        log.error(f"{jd_path} file not found", console, False)
        sys.exit(1)
    except Exception:
        log.error("An error occurred: {e}", console, False)
        sys.exit(1)


def shell_safe_path(path):
    return shlex.quote(path)


def scan(dir: str, mode: str, output_file: str):
    cmd = []
    cmd_string = ""
    check_path(dir)
    try:
        process = subprocess.Popen(
            ["semgrep", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate()
    except Exception:
        log.error("Failed to invoke Opengrep. Exiting.", console, False)
        sys.exit(1)

    try:
        source_dict: dict = SourceHandler().get_sources_by_type(mode)
        configs = source_dict["sources"]
        cmd = [
            "opengrep",
            "scan",
            "--json",
            "--taint-intrafile",
            "--exclude=sitgrep-report*",
            "--exclude=sitgrep-config.json",
            "--exclude=semgrep_output.json",
            "--exclude=tst",
            "--exclude=tests",
            "--no-git-ignore",
            f"-o opengrep-scan-{TIMESTR}",
        ]

        if VERBOSE_LEVEL > 2:
            cmd.extend(["--debug"])
        elif VERBOSE_LEVEL == 2:
            cmd.extend(["--verbose"])

        if not LOCAL_MODE:
            cmd.extend(["--config", "auto"])

        for config in configs:
            config_path = os.path.join(INSTALL_DIR, "rules", config["id"])
            if os.path.isdir(config_path) or os.path.isfile(config_path):
                if not LOCAL_MODE and config["id"] == "semgrep":
                    continue
                cmd.extend(["--config", config_path])
            else:
                log.warn(f"Config path {config_path} not found. Skipping...")

        cmd.extend([shell_safe_path(dir)])

        cmd_string = " ".join(cmd)
        output = {}
        log.info("Starting Opengrep...")
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            SpinnerColumn(),
            transient=True,
        ) as progress:
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
                task1 = progress.add_task(
                    log.get_info("Opengrep is loading rules..."), total=None
                )
                task2 = progress.add_task(
                    log.get_info("Scanning..."),
                    start=False,
                    visible=False,
                )
                progress.update(task1)
                lines = []

                while True:
                    line = process.stdout.readline()
                    if line == "" and process.poll() is not None:
                        break

                    if line.strip() != "":
                        isScanning = True

                    if isScanning:
                        progress.update(task1, visible=False)
                        progress.update(task2, visible=True)

                        if VERBOSE_LEVEL > 0:
                            if '{"errors' not in line:
                                lines.append(line.strip())

                    if "scanning 0 files" in line.lower():
                        raise BadScanException

        raw_semgrep_output = "\n".join(lines)

        if VERBOSE_LEVEL > 0:
            console.print(Panel.fit(raw_semgrep_output, title="Opengrep output"))

        process.wait()

        if os.path.isfile(f"opengrep-scan-{TIMESTR}"):
            with open(f"opengrep-scan-{TIMESTR}") as output:
                try:
                    output = json.loads(str(output.read()))
                    os.remove(f"opengrep-scan-{TIMESTR}")
                except Exception:
                    log.error(
                        "Error occurred while loading the output for parsing", console
                    )
                    sys.exit(1)
        else:
            raise BadScanException
        save_raw_semgrep_output(output)

        if VERBOSE_LEVEL > 0:
            console.print("\n")
            # log.info("-------------- Opengrep output end --------------")
            log.info("Opengrep command used: ")
            console.print(
                Syntax(cmd_string, "bash", word_wrap=True, padding=(0, 0, 0, 12))
            )
            console.print("\n")
            log.info(
                f"The raw Opengrep JSON output was saved to {os.getcwd() + '/semgrep_output.json'}"
            )
        log.info("Opengrep scan complete..")

        return output

    except BadScanException as bse:
        console.print()
        # if VERBOSE_LEVEL > 0:
        #     log.info("-------------- Opengrep output end --------------")
        log.error(
            "Opengrep scan failed. Check if the specified directory is listed in a .gitignore file for the project being scanned. The specified directory or the results may also be empty.",
            console,
            False,
        )
        log.error(str(bse), console, False)
        log.info("Opengrep command: ")
        console.print(Syntax(cmd_string, "bash", word_wrap=True, padding=(0, 0, 0, 12)))
        try:
            os.remove(f"opengrep-scan-{TIMESTR}")
        except Exception:
            pass
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        console.print()
        # if VERBOSE_LEVEL > 0:
        #     log.info("-------------- Opengrep output end --------------")

        log.error(f"Opengrep returned with errors: {e.stdout}", console, False)
        log.info("Opengrep command: ")
        console.print(Syntax(cmd_string, "bash", word_wrap=True, padding=(0, 0, 0, 12)))
        try:
            os.remove(f"opengrep-scan-{TIMESTR}")
        except Exception:
            pass
        sys.exit(1)

    except FileNotFoundError:
        log.error(f"The specified directory could not be found: {dir}", console, False)
        sys.exit(1)

    except Exception:
        console.print()
        if VERBOSE_LEVEL > 0:
            # log.info("-------------- Opengrep output end --------------")
            log.info("Opengrep command: ")
            console.print(
                Syntax(cmd_string, "bash", word_wrap=True, padding=(0, 0, 0, 12))
            )
        log.error("An error occurred", console)
        try:
            os.remove(f"opengrep-scan-{TIMESTR}")
        except Exception:
            pass
        sys.exit(1)


def getPackageName(file_path, packages):
    for package_obj in packages:
        for file in file_path.split("/"):
            if file.lower() == package_obj["project"].lower():
                return file
    return ""


def safe_invoke(tool, args):
    valid_keys = tool.args.keys()
    filtered = {k: v for k, v in args.items() if k in valid_keys}
    return tool.invoke(filtered)


def process_json(results, dir, packages, AGENTIC=False) -> dict:

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

            encoding = detect_encoding(file_path)
            with open(file_path, "r", encoding=encoding) as f:
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

                home = (
                    str(Path(os.path.join(INSTALL_DIR, "rules")).absolute().resolve())
                    .replace(os.sep, ".")
                    .replace(".", "", 1)
                )
                rule_id: str = result["check_id"].replace(home, "")
                rule_id = rule_id.removeprefix(".")
                rule_parts = rule_id.split(".")
                rule_id = f"{rule_parts[0]}.{rule_parts[-1]}"

                rule_index = get_rule_index(json_results["results"], rule_id)

                new_file_path = f"{file.replace(os.path.abspath(dir), '')}"
                if new_file_path.startswith("/"):
                    new_file_path = new_file_path[1:]

                id = (
                    f"{groupIndex}::{0}"
                    if rule_index == -1
                    else f"{json_results['results'][rule_index]['id']}::{len(json_results['results'][rule_index]['findings'])}"
                )

                finding = {
                    "id": id,
                    "file": new_file_path,
                    "package": package_name,
                    "context": context,
                    "end": result["end"]["line"],
                    "start": result["start"]["line"],
                    "file_size": len(lines),
                    "fullFile": file,
                }

                if AGENTIC:
                    finding["agent_review"] = result.get("agent_review", "")

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
                            "findings": [finding],
                        }
                    )
                    groupIndex += 1
                else:
                    json_results["results"][rule_index]["findings"].append(finding)

        return json_results
    except KeyError:
        log.error("The following key could not be found while parsing JSON", console)
        sys.exit(1)
    except Exception:
        log.error("Error parsing JSON", console)
        sys.exit(1)


def get_rule_index(results: list, rule_id):
    for index, result in enumerate(results):
        if result.get("rule_id") == rule_id:
            return index
    return -1


def count_findings(results):
    return sum(len(rule["findings"]) for rule in results["results"])


def save_results(scan_results: dict, output_file, dir="", packages=[], AGENTIC=False):

    try:
        processed_results: dict = process_json(
            scan_results["results"], dir, packages, AGENTIC=AGENTIC
        )
        processed_results["packages"] = packages
        processed_results["contextLength"] = CONTEXT_LINE_COUNT

        if len(processed_results) > 0:
            try:
                goto_output_dir()
                if not AGENTIC:
                    base = open(
                        f"{INSTALL_DIR}/web/templates/template.html", "r"
                    ).read()

                    with open(f"{output_file}.html", "a") as html_file:
                        html_file.write(base)
                    os.mkdir("static")
                    shutil.copytree(f"{INSTALL_DIR}/web/static/js", "static/js")
                    shutil.copytree(f"{INSTALL_DIR}/web/static/css", "static/css")
                    shutil.copytree(f"{INSTALL_DIR}/web/static/img", "static/img")

                    if not os.path.isdir("results"):
                        os.mkdir("results")

                with open("results/results.js", "w") as js_file:
                    js_file.write(
                        f"const sitgrep_results = {json.dumps(processed_results)}"
                    )
                output_file_location = os.path.abspath("{}.html".format(output_file))
                if AGENTIC:
                    log.success(
                        f"Agentic results have been saved to file://{output_file_location}"
                    )
                else:
                    log.info(
                        f"Scan results: {count_findings(processed_results)} findings after scanning {len(scan_results['paths']['scanned'])} files"
                    )
                    log.success(
                        f"Results have been saved to file://{output_file_location}"
                    )

                    if not NO_OPEN:
                        if os.environ.get("WSL_DISTRO_NAME", "none") == "none":
                            webbrowser.open_new_tab(f"file://{output_file_location}")
                        else:
                            os.chdir(
                                f"{'/'.join(output_file_location.split('/')[:-1])}"
                            )
                            webbrowser.open_new_tab(f"{output_file}.html")

            except FileExistsError as e:
                log.error(f"The file already exists: {e}", console, False)
                sys.exit(-1)
            except Exception:
                log.error("There was an error saving the file: ", console, True)
                sys.exit(-1)
        else:
            log.success("Congrats, there were no findings.")
    except Exception:
        log.error("There was an error saving the output: ", console, True)
        # traceback.print_exc()
        sys.exit(-1)


def goto_output_dir():
    os.chdir(OUTPUT_FOLDER)


def handle_clone_failure(error: str):
    log.error("A package clone failed", console, False)
    option = input("\tDo you wish to continue? (y/n): ")

    if option.lower().strip().startswith("n"):
        log.info("Cancelling scan...")
        log.error(error, console, False)
        sys.exit(1)


def create_output_dir():
    os.chdir(START_DIR)

    if not os.path.isdir("sitgrep-report"):
        os.mkdir("sitgrep-report")

    if not os.path.isdir(OUTPUT_FOLDER):
        os.mkdir(OUTPUT_FOLDER)
    else:
        log.error(
            "Output directory already exists. Cannot overwrite previous reports",
            console,
            False,
        )


def save_raw_semgrep_output(results: object):
    goto_output_dir()
    with open("semgrep_output.json", "w") as output:
        json.dump(results, output, indent=4)


def agent_analyze(
    model: model.OllamaModel, scan_results: dict, directory: str, agent_endpoint: str
) -> dict:

    agent = SitgrepAgent(model, directory, agent_endpoint)
    agent.start()
    TOTAL = len(scan_results["results"])

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        SpinnerColumn(),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
        transient=True,
        speed_estimate_period=900,
    ) as progress:
        task = progress.add_task(
            log.get_info("SitgrepAI analyzing findings"), total=TOTAL
        )
        for result in scan_results["results"]:
            # Init Agent
            context = {}
            context["ai_bot_scope"] = directory
            context["file_path"] = result["path"]
            context["start"] = result["start"]
            context["end"] = result["end"]
            context["code"] = result["extra"]["lines"]
            context["description"] = result["extra"]["message"]
            context["confidence"] = result["extra"]["metadata"]["confidence"]
            context["severity"] = result["extra"]["metadata"]["impact"]
            context["likelihood"] = result["extra"]["metadata"]["likelihood"]

            # Keep going until limit met or engineer is done
            state = {
                "messages": [
                    HumanMessage(content=f"Here is the context: {str(context)}")
                ],
                "iteration": 0,
                "done": False,
            }
            LIMIT = 10
            progress.update(
                task, description=log.get_info("Agent: Analyzing..."), advance=1
            )
            while state["iteration"] <= LIMIT and not state["done"]:
                state["iteration"] += 1
                progress.update(task, description=log.get_info("Agent: Analyzing..."))

                engineer_input = str({"context": context, "history": state["messages"]})

                try:
                    engineer_raw = agent.send(AgentType.ENGINEER, engineer_input)

                    if VERBOSE_LEVEL > 2:
                        log.debug(engineer_raw)

                    engineer_output = get_ai_message(engineer_raw, AgentType.ENGINEER)

                    state["messages"].append(
                        HumanMessage(content=f"Engineer output: {engineer_output}")
                    )

                    state["done"] = engineer_output.get("done", False)

                    if state["done"] or state["iteration"] > 2:
                        judge_result: BaseModel = get_ai_message(
                            agent.send(
                                AgentType.JUDGE,
                                str({"chat_history": str(state["messages"])}),
                            ),
                            AgentType.JUDGE,
                        )  # type: ignore
                        result["agent_review"] = judge_result
                        break

                    try:
                        tool_name, args = extract_tools_invocation(
                            engineer_output, agent.tool_map
                        )  # type: ignore
                        tool_call_result = ""

                        if tool_name in agent.tool_map:
                            tool_call_result = safe_invoke(
                                agent.tool_map[tool_name], args
                            )
                            if VERBOSE_LEVEL > 1:
                                log.debug(tool_call_result)
                        else:
                            raise ValueError(f"Unknown tool: {tool_name}")

                        state["messages"].append(
                            ToolMessage(
                                content=str(tool_call_result).replace("\n", "\\n"),
                                tool_call_id=tool_name,
                            )
                        )

                    except Exception as tool_e:
                        log.error(f"Tool error: {tool_e}", console)
                except Exception as e:
                    log.error(f"Error calling agent: {e}", console)

            # Restart bot to preserve stability
            agent.restart(True)

    progress.update(
        task, description=log.get_info("Agent analyses complete..."), completed=True
    )
    # Once done, stop the agent
    agent.stop()
    log.info("Agent: Analysis completed")
    return scan_results


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
        except Exception:
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


def get_url_for_site(
    project_name: str, package_details: dict, with_ssh: bool, site: str
) -> str:
    match site:
        case "github":
            if with_ssh:
                return f"git@github.com:{package_details['path']}/{project_name}.git"
            else:
                return (
                    f"https://github.com/{package_details['path']}/{project_name}.git"
                )
        case "gitlab":
            if with_ssh:
                return f"git@gitlab.com:{package_details['path']}/{project_name}.git"
            else:
                return (
                    f"https://gitlab.com/{package_details['path']}/{project_name}.git"
                )
        case _:
            log.error(
                "Only Github and Gitlab are supported.",
                console=console,
                showException=True,
            )
            sys.exit(1)


def get_env(with_ssh: bool, ssh_key_path: str) -> dict:
    env = os.environ.copy()
    if with_ssh and ssh_key_path != "":
        if ssh_key_path != "":
            env["GIT_SSH_COMMAND"] = f"ssh -i {ssh_key_path} -o IdentitiesOnly=yes"
        else:
            env.pop("GIT_SSH_COMMAND", None)
    return env


def clone_repo(
    failed_packages: list,
    package_details: dict,
    progress_bar: ProgressBar,
    protocol: str,
    key: str,
):
    project_name = package_details["project"]
    branch = (
        package_details["branch"].strip()
        if package_details["branch"].strip() != ""
        else None
    )

    with_ssh = True if protocol == "SSH" else False
    repo_url: str = get_url_for_site(
        project_name=project_name,
        package_details=package_details,
        with_ssh=with_ssh,
        site=package_details["site"],
    )

    def check_git_access(project_name, package_details, key=""):
        project_name.replace(".git", "")

        env = get_env(with_ssh, ssh_key_path)
        env["GIT_TERMINAL_PROMPT"] = "0"

        # Attempt to list remote references without providing credentials
        process = subprocess.Popen(
            ["git", "ls-remote", repo_url],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            encoding="utf-8",
            env=env,
        )

        no_auth_needed = True

        for line in process.stdout:
            if (
                "username" in line.lower()
                or "fatal" in line.lower()
                or "passphrase" in line.lower()
                or "permission denied" in line.lower()
            ):
                no_auth_needed = False
                process.kill()
            else:
                no_auth_needed = True

        # Wait for process to finish
        process.wait()
        site = package_details["site"]
        if no_auth_needed:
            return False
        elif not with_ssh:
            username = Prompt.ask(f"Username for {site}")
            password = Prompt.ask(f"Passphrase for {site}", password=True)
            os.environ["GIT_USERNAME"] = username
            os.environ["GIT_PASSWORD"] = password
        elif with_ssh and key.strip() != "":
            try:
                subprocess.run(
                    ["ssh-add", key], stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                log.info(f"Adding SSH key {key} to SSH agent...")
                return True
            except subprocess.CalledProcessError as e:
                log.error(f"Error adding SSH key: {e.stderr.decode()}", console, False)
        return False

    def handle_failed_package(failed_packages, project_name, error):
        failed_packages.append({"package": f"{project_name}", "error": error})

    try:
        check_path(os.path.expanduser(key.strip()))
    except FileNotFoundError:
        log.error(f"The specified key could not be found: {key}", console, False)
        sys.exit(1)

    ssh_key_path = os.path.expanduser(key.strip()).strip()
    env = get_env(with_ssh, ssh_key_path)
    added_ssh_key = False

    try:
        if package_details["site"].lower() in ["github", "gitlab"]:
            if branch == "main":
                branch = None

        added_ssh_key = check_git_access(
            project_name, package_details, key=ssh_key_path
        )

        progress_bar.start()
        Repo.clone_from(
            url=repo_url,
            to_path=f"{os.getcwd()}/{project_name}",
            multi_options=["--single-branch"],
            branch=branch,
            progress=progress_bar,
            depth=1,
            jobs=4,
            env=env,
        )

        os.chdir(project_name)
        with open("sitgrep-config.json", "w") as config_file:
            json.dump(package_details, config_file)
        progress_bar.stop()
        os.chdir("../")
        env.pop("GIT_SSH_COMMAND", None)
        if added_ssh_key and protocol == "SSH":
            choice = Prompt.ask(
                log.get_warn(
                    "Would you like to keep the SSH key in the SSH agent to avoid entering the password to this key in the future? (y/n)"
                )
            )
            if choice.lower().startswith("n"):
                subprocess.run(["ssh-add", "-d", key], check=True)
                log.info(f"Removing SSH key {key} from SSH agent...")

    except GitCommandError as e:
        console.print()
        error_log = f"The repository wasn't found, you do not have access, or another error occurred. If using an SSH key with a password, please provide the path to the SSH key using the --ssh-key parameter. \n{e}"
        progress_bar.stop()
        handle_failed_package(failed_packages, project_name, error_log)
    except subprocess.SubprocessError:
        pass
    except Exception as e:
        console.print()
        error_log = f"Error while downloading package - {e}"
        progress_bar.stop()
        handle_failed_package(failed_packages, project_name, error_log)


def download_packages(packages: list, protocol: str, key: str = ""):
    has_warned = False

    failed_packages = []

    if os.path.isdir("Sitgrep_Packages"):
        shutil.rmtree("Sitgrep_Packages")

    os.mkdir("Sitgrep_Packages")
    os.chdir("Sitgrep_Packages")

    log.info(f"Downloading {len(packages)} package(s)...")

    for package in packages:
        progress_bar = ProgressBar(target=package["project"])
        clone_repo(failed_packages, package, progress_bar, protocol, key)

    if len(failed_packages) == len(packages):
        console.print()
        log.error("All packages failed to download.", console, False)

        for failed_package in failed_packages:
            log.error(
                f"Package {failed_package['package']}: {failed_package['error']}",
                console,
                False,
            )

        if LOCAL_MODE and has_warned:
            log.warn(
                "Ensure you have run the following commands:\n\n* mwinit -o\n* kinit\n\n"
            )

        sys.exit(1)

    else:
        if len(failed_packages) > 0:
            console.print()
            log.error(
                "The following packages failed to be downloaded:\n", console, False
            )
            for failed_package in failed_packages:
                log.error(
                    f"Package {failed_package['package']}: {failed_package['error']}",
                    console,
                    False,
                )
            console.print()
        else:
            log.info(
                f"Successfully downloaded {len(packages) - len(failed_packages)} package(s)"
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
                    log.error(f"Unable to parse Github URL: {package}", console, True)

                split_packages.append(
                    {
                        "path": parsed_github_url["path"],  # type: ignore
                        "project": parsed_github_url["project"],  # type: ignore
                        "branch": parsed_github_url["branch"],  # type: ignore
                        "user": parsed_github_url["user"],  # type: ignore
                        "site": "github",
                    }
                )

            elif "gitlab.com" in package and mode == "gitlab":
                parsed_gitlab_url = parse_gitlab_url(package)

                if not parsed_gitlab_url or parsed_gitlab_url is None:
                    log.error(f"Unable to parse Github URL: {package}", console, True)

                split_packages.append(
                    {
                        "path": parsed_gitlab_url["path"],  # type: ignore
                        "project": parsed_gitlab_url["project"],  # type: ignore
                        "branch": parsed_gitlab_url["branch"],  # type: ignore
                        "user": parsed_gitlab_url["user"],  # type: ignore
                        "site": "gitlab",
                    }
                )
            else:
                log.error(
                    "Could not parse URL. Only Github and Gitlab links are currently supported.",
                    console,
                    False,
                )
                log.info("Please report this so this usecase can be added.")
        else:
            log.error(f"Unable to parse package: {package}", console)

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
        except Exception:
            log.error("There was an error parsing the package list: ", console, True)
            sys.exit(1)

    else:
        log.error(
            f"Unsupported type: Expected a text file or a list of packages, not {type(packages)}",
            console,
            False,
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
    except Exception:
        folder_uri = urlparse(dir)
        vscode_link = f"vscode://file/{folder_uri.path}"
        webbrowser.open(vscode_link)


def rgb_gradient(start_rgb, end_rgb, steps):
    """
    Generate a list of RGB colors between start_rgb and end_rgb.
    - start_rgb: tuple (r, g, b) for the starting color
    - end_rgb: tuple (r, g, b) for the ending color
    - steps: number of steps in the gradient
    """
    gradient = []
    for step in range(steps):
        r = int(start_rgb[0] + (end_rgb[0] - start_rgb[0]) * (step / (steps - 1)))
        g = int(start_rgb[1] + (end_rgb[1] - start_rgb[1]) * (step / (steps - 1)))
        b = int(start_rgb[2] + (end_rgb[2] - start_rgb[2]) * (step / (steps - 1)))
        gradient.append(f"rgb({r},{g},{b})")
    return gradient


def generate_rainbow_gradient(steps):
    # Rainbow colors in RGB
    rainbow_colors = [
        # (255, 0, 0),    # Red
        # (255, 165, 0),  # Orange
        # (255, 255, 0),  # Yellow
        (0, 255, 0),  # Green
        (0, 255, 255),  # Cyan
        (0, 0, 255),  # Blue
        # (238, 130, 238) # Violet
    ]

    # We want to create a smooth gradient between these colors
    full_gradient = []

    # Interpolate between each pair of adjacent rainbow colors
    for i in range(len(rainbow_colors) - 1):
        full_gradient.extend(
            rgb_gradient(
                rainbow_colors[i],
                rainbow_colors[i + 1],
                steps // (len(rainbow_colors) - 1),
            )
        )

    return full_gradient


def print_banner(directory, output_file):

    banner = "Context lines: " + str(CONTEXT_LINE_COUNT) + "\n"
    banner += "Directory to scan: " + str(directory) + "\n"
    banner += "Output file: " + str(output_file) + "\n"
    banner += "Version: " + str(VERSION) + "\n"

    banner_len = min(
        os.get_terminal_size().columns, max([len(a) for a in banner.split("\n")])
    )

    banner = (
        "\n".join(
            [
                a.center(banner_len, " ")
                for a in r"""
┌─────────────────────┐
│       Sitgrep       │
│                     │
│ Powered by Opengrep │
└─────────────────────┘
""".split("\n")
            ]
        )
        + "\n"
        + banner
    )

    banner = "-" * banner_len + "\n" + banner + "\n" + "-" * banner_len

    # Generate the RGB gradient across the banner length
    gradient = generate_rainbow_gradient(banner_len)

    newbanner = Text("")

    for line in [a for a in banner.split("\n") if a != ""]:
        newline = Text("")
        for i, chr in enumerate([a for a in line]):
            try:
                color = gradient[i]
                newline.append(f"{chr}", style=color)
            except IndexError:
                pass
        newbanner.append(newline)
        newbanner.append(Text("\n"))

    console.print(newbanner)


def start_scan(directory, output_file, packages, args, ALLOW_DOWNLOAD):

    has_key = False
    if hasattr(args, "ssh_key") and args.ssh_key:
        try:
            check_path(os.path.expanduser(args.ssh_key))
            has_key = True
        except FileNotFoundError:
            log.error(
                f"The specified SSH key could not be found: {args.ssh_key}",
                console,
                False,
            )
            sys.exit(1)

    if LOCAL_MODE and len(packages) > 0 and ALLOW_DOWNLOAD:
        (
            download_packages(packages, args.protocol, args.ssh_key)
            if has_key
            else download_packages(packages, args.protocol)
        )

        if args.no_scan:
            sys.exit(1)
    elif LOCAL_MODE:
        if len(packages) == 0:
            packages = get_packages_from_dir(directory)

    elif len(packages) > 0 and ALLOW_DOWNLOAD:
        (
            download_packages(packages, args.protocol, args.ssh_key)
            if has_key
            else download_packages(packages, args.protocol)
        )

    scan_results = scan(directory, args.mode, output_file)

    try:
        if "results" in scan_results and len(scan_results["results"]) > 0:
            save_results(scan_results, output_file, directory, packages)
            if (
                not hasattr(args, "github")
                and not hasattr(args, "gitlab")
                and hasattr(args, "vscode")
            ):
                open_dir_in_vscode(dir=directory)

            if AGENT_ENABLED:
                results = agent_analyze(
                    args.model, scan_results, directory, args.agent_endpoint
                )
                save_results(results, output_file, directory, packages, AGENTIC=True)

        elif "errors" in scan_results and len(scan_results["errors"]) > 0:
            valid_errors = []
            for error in scan_results["errors"]:
                if (
                    "missing plugin" not in str(error["type"]).casefold()
                    and "syntax error" not in str(error["message"]).casefold()
                ):
                    valid_errors.append(error)
            if len(valid_errors) > 0:
                log.error(
                    "Opengrep encountered errors and returned no results:",
                    console,
                    False,
                )
                log.error(valid_errors, console, False)
            else:
                log.success("Congrats, there were no findings.")
        elif len(scan_results["results"]) == 0:
            log.success("Congrats, there were no findings.")
        elif (
            "results" not in scan_results
            and "errors" not in scan_results
            and "paths" not in scan_results
        ):
            log.error(
                "There was an error with Opengrep and the results returned null. Please report this issue.",
                console,
                False,
            )
    except Exception:
        if hasattr(args, "agent"):
            agent.SitgrepAgent(args.model).kill_ollama()
        log.error("There was an error: ", console)


def main(args):
    directory = os.path.abspath(args.directory)
    directory = extract_if_archive(directory)
    global CONTEXT_LINE_COUNT
    CONTEXT_LINE_COUNT = args.context

    global VERBOSE_LEVEL
    VERBOSE_LEVEL = args.verbose

    global LOCAL_MODE
    LOCAL_MODE = False

    global NO_OPEN
    NO_OPEN = args.no_auto_open

    ALLOW_DOWNLOAD = False
    global OUTPUT_FOLDER

    global AGENT_ENABLED
    AGENT_ENABLED = args.agent

    packages = []
    output_file = args.output
    if str(args.output).strip() == "" or args.output is None:
        output_file = f"sitgrep-{TIMESTR}"
        OUTPUT_FOLDER = os.path.join(START_DIR, "sitgrep-report", f"sitgrep-{TIMESTR}")
    else:
        output_file = args.output
        OUTPUT_FOLDER = os.path.join(
            START_DIR, "sitgrep-report", f"{args.output}-{TIMESTR}"
        )

    create_output_dir()

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
                log.error(
                    f"The JSON could not be found at the given path: {expanded_filepath}",
                    console,
                    False,
                )
        except Exception:
            log.error("There was an error loading the JSON file: ", console)
            sys.exit(1)
    elif args.subcommands == "local":
        LOCAL_MODE = True

    # Check for the --jar_file argument and decompile the JAR
    if args.jar_file:
        jar_file_path = START_DIR
        if os.path.isabs(args.jar_file):
            jar_file_path = args.jar_file
        else:
            jar_file_path = os.path.join(START_DIR, args.jar_file)
        if not os.path.isfile(jar_file_path):
            log.error(f"The JAR file {jar_file_path} does not exist.", console)
            sys.exit(1)

        if not ensure_program_installed("java"):
            sys.exit(1)

        if not ensure_environment_set("JAVA_HOME"):
            sys.exit(1)

        decompiled_dir = os.path.join(directory, "sitgrep_jar_decompiled")
        if not os.path.exists(decompiled_dir):
            os.makedirs(decompiled_dir)

        jar_name = os.path.basename(jar_file_path)
        decompiled_src_dir = os.path.join(decompiled_dir, f"{jar_name}_src")
        if not os.path.exists(decompiled_src_dir):
            os.makedirs(decompiled_src_dir)

        decompile_jar(jar_file_path, decompiled_src_dir)
        directory = decompiled_src_dir

    try:
        if not hasattr(args, "github") and not hasattr(args, "gitlab"):
            packages = get_packages_from_dir(directory)
        elif hasattr(args, "github") or hasattr(args, "gitlab"):
            ALLOW_DOWNLOAD = True

            github_packages: list = []
            gitlab_packages: list = []

            if (
                hasattr(args, "github")
                and isinstance(args.github, list)
                and len(args.github) > 0
            ):
                github_packages = get_package_list(args.github)
                github_packages = strip_package_names(github_packages)
                github_packages = split_packages(github_packages, mode="github")
                directory = (
                    os.path.join(directory, "Sitgrep_Packages")
                    if "Sitgrep_Packages" not in directory
                    else directory
                )
            if (
                hasattr(args, "gitlab")
                and isinstance(args.gitlab, list)
                and len(args.gitlab) > 0
            ):
                gitlab_packages = get_package_list(args.gitlab)
                gitlab_packages = strip_package_names(gitlab_packages)
                gitlab_packages = split_packages(gitlab_packages, mode="gitlab")
                directory = (
                    os.path.join(directory, "Sitgrep_Packages")
                    if "Sitgrep_Packages" not in directory
                    else directory
                )

            packages = github_packages + gitlab_packages

        else:
            directory = os.path.abspath(directory)
            if not os.path.isdir(directory) and not os.path.isfile(directory):
                raise (FileNotFoundError)
    except FileNotFoundError:
        log.error(
            f"The directory specified could not be found: {directory}", console, False
        )
        sys.exit(1)
    except Exception:
        if hasattr(args, "github") or hasattr(args, "gitlab"):
            log.error("There was an error gathering package data: ", console)
        else:
            log.error(
                "There was an error parsing the directory of the package: ",
                console,
            )
        sys.exit(1)

    print_banner(directory=directory, output_file=output_file)
    start_scan(directory, output_file, packages, args, ALLOW_DOWNLOAD)


def cli():
    parser = argparse.ArgumentParser(formatter_class=RichHelpFormatter)

    subparsers = parser.add_subparsers(dest="subcommands")
    source_handler = SourceHandler()
    sources_parser = subparsers.add_parser(
        "sources",
        help="Manage sources",
    )
    sources_subparsers = sources_parser.add_subparsers(dest="action", required=True)

    update_parser = sources_subparsers.add_parser("add", help="Add a rule source")
    update_parser.add_argument("--id", required=True, help="Name/ID of the source")
    update_parser.add_argument("--url", required=True, help="URL of the source")
    update_parser.add_argument(
        "--categories",
        type=validate_mode,
        required=True,
        help=f"Categories of the source. Valid categories: {MODES}",
    )
    update_parser.set_defaults(func=source_handler.add_source)

    delete_parser = sources_subparsers.add_parser("delete", help="Delete a rule source")
    delete_parser.add_argument("--id", required=True, help="Name/ID of the source")
    delete_parser.set_defaults(func=source_handler.delete_source)

    list_parser = sources_subparsers.add_parser("list", help="List all rule sources")
    list_parser.set_defaults(func=source_handler.list_sources)

    restore_parser = sources_subparsers.add_parser(
        "restore", help="Restore original sources"
    )
    restore_parser.set_defaults(func=source_handler.restore_sources)

    fetch_parser = sources_subparsers.add_parser("fetch", help="Fetch all rule sources")
    fetch_parser.set_defaults(func=source_handler.fetch_sources)

    export_parser = sources_subparsers.add_parser(
        "export", help="Export rules to ZIP file"
    )
    export_parser.add_argument(
        "--output",
        required=False,
        default=os.getcwd(),
        help="Location to output zip file",
    )
    export_parser.set_defaults(func=source_handler.export_rules)

    local_parser = subparsers.add_parser(
        "local",
        help="Use local rules instead of official Opengrep rules. Run 'sitgrep local -h' for more info.",
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
        help="Only download packages, do not scan them. (default=False)",
    )
    local_parser.add_argument(
        "-ai",
        "--agent",
        required=False,
        action="store_true",
        help="Enable AI agent to review output.",
    )
    local_parser.add_argument(
        "-l",
        "--model",
        required=False,
        choices=model.OllamaModel.toList(),
        default=model.OllamaModel.QWEN3_14B,
        type=model.OllamaModel,
        help=f"Specify mode. Valid modes: {model.OllamaModel.toList()}",
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
        help="Load a Opengrep JSON output file",
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
        "-jf",
        "--jar_file",
        required=False,
        type=str,
        help="Specify full path to JAR.",
    )
    local_parser.add_argument(
        "-m",
        "--mode",
        required=False,
        choices=MODES,
        default="GENERAL",
        type=str,
        help=f"Specify mode. Valid modes: {MODES}",
    )
    local_parser.add_argument(
        "-p",
        "--protocol",
        required=False,
        choices=PROTOCOLS,
        default="SSH",
        type=str.upper,
        help=f"Specify mode. Valid protocols: {PROTOCOLS}",
    )
    local_parser.add_argument(
        "-i",
        "--ssh-key",
        required=False,
        type=str,
        help="Specify SSH key to use.",
    )
    local_parser.add_argument(
        "-ae",
        "--agent-endpoint",
        required=False,
        type=str,
        help="URL to the agent endpoint",
        default="",
    )

    local_parser.add_argument(
        "-vs", "--vscode", action="store_true", help="Open the folder in VSCode"
    )
    parser.add_argument(
        "-m",
        "--mode",
        required=False,
        choices=MODES,
        default="GENERAL",
        type=str,
        help=f"Specify mode. Valid modes: {MODES}",
    )
    parser.add_argument(
        "-p",
        "--protocol",
        required=False,
        choices=PROTOCOLS,
        default="SSH",
        type=str.upper,
        help=f"Specify mode. Valid protocols: {PROTOCOLS}",
    )
    parser.add_argument(
        "-i",
        "--ssh-key",
        required=False,
        type=str,
        help="Specify SSH key to use.",
    )
    parser.add_argument(
        "-ai",
        "--agent",
        required=False,
        action="store_true",
        help="Enable AI agent to review output.",
    )
    parser.add_argument(
        "-l",
        "--model",
        required=False,
        choices=model.OllamaModel,
        default=model.OllamaModel.QWEN3_14B,
        type=model.OllamaModel,
        help=f"Specify mode. Valid modes: {model.OllamaModel.toList()}",
    )
    parser.add_argument(
        "-c",
        "--context",
        default=5,
        type=int,
        help="The amount of context lines above and below to save (default=5)",
    )
    parser.add_argument(
        "-jf",
        "--jar_file",
        required=False,
        type=str,
        help="Specify full path to JAR.",
    )
    parser.add_argument(
        "-ae",
        "--agent-endpoint",
        required=False,
        type=str,
        help="URL to the agent endpoint",
        default="",
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
        help="Load a Opengrep JSON output file",
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
    if hasattr(args, "func"):
        args.func(args)
    try:
        main(args)
    except KeyboardInterrupt:
        console.print("\r\n", end="\r")
        if hasattr(args, "agent"):
            agent.SitgrepAgent(args.model).kill_ollama()
        log.warn("Detected keyboard interrupt. Exiting...")
    except MemoryError:
        if hasattr(args, "agent"):
            agent.SitgrepAgent(args.model).kill_ollama()
        log.error(
            "Ran out of memory. Please report this package for further investigation.",
            console,
            False,
        )
        sys.exit(2)
    except FileNotFoundError:
        if hasattr(args, "agent"):
            agent.SitgrepAgent(args.model).kill_ollama()
        log.error(
            f"The directory specified could not be found: {args.directory}",
            console,
            True,
        )
        sys.exit(3)
    except Exception:
        if hasattr(args, "agent"):
            agent.SitgrepAgent(args.model).kill_ollama()
        console.print()
        log.error("An unknown exception occured", console, True)
