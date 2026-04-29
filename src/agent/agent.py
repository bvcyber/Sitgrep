import os
import sys
import time
import subprocess
import requests
from pathlib import Path
from typing import List, Optional
from langchain.agents import create_agent
from langchain_core.tools import BaseTool
from langchain_ollama import ChatOllama
from agent.agents import engineer, judge
from utils import logging as log
from pydantic import Field
import psutil
from rich.console import Console
from rich.traceback import install
from langchain.tools import tool
import json
from agent.agents.types import AgentType
from langchain.messages import HumanMessage, SystemMessage
import concurrent.futures

install(show_locals=True)
console = Console(color_system="truecolor")

BASE_DIR: str = "."
OLLAMA_URL = "http://localhost:11434"

@tool
def opengrep_search(pattern: str, language: str):
    """
    Search for code patterns using Opengrep, which is a Semgrep fork.
    You MUST use this to find specific function implementations.

    You will call the command with the appropriate --pattern. The --lang parameter is the language of the code you want to find.
    You MUST include the body block that is appropriate for the language, otherwise you won't get the function definition returned and everyone dies because of you.
    The body block is language dependent, but the content inside the body of the function MUST be generalized as "...".
    Be absolutely sure that the function name matches the one seen in the code, including capitalization.

    Commands and patterns will look like the following for examples:

    `semgrep --lang python --pattern "def $FUNC(...): ..." --json /some/path/to/code `
    `semgrep --lang javascript --pattern "function $FUNC(...) { ... }" --json /some/path/to/code `

    Do NOT try to use YAML syntax.
    Be sure to tweak this for each language and context. DO NOT use these examples directly. Craft your own patterns based on the code you are given and then ensure the pattern has a function body.

    """
    try:
        result = subprocess.run(
            [
                "opengrep",
                "scan",
                "-e",
                pattern,
                "--max-lines-per-finding",
                "30",
                "-l",
                language,
                "--no-git-ignore",
                "--json",
                BASE_DIR,
            ],
            capture_output=True,
            text=True,
        )
        data = json.loads(result.stdout)
        return data if data else "No context found."
    except Exception as e:
        return f"Opengrep error: {str(e)}"


@tool
def grep_search(pattern, isRegex=False) -> str:
    """
    Searches for pattern either directly or using regex. Use for when opengrep_search fails, function calls, or for plaintext documents.
    Keep patterns simple. For example, if looking for a function call, only use a single name, not something like class.mymethod(), but rather just "mymethod" in order to have greater success in finding it.
    Do NOT use this for variables or function parameters/arguments. Use read_file_chunk instead for variables and function parameters/arguments.
    """
    result = None

    def sanitize_pattern(pattern: str):
        return pattern.replace("(", "").replace("\\", "").replace('"', '"')

    pattern = sanitize_pattern(pattern)

    try:
        if not isRegex:
            result = subprocess.run(
                ["grep", "-rinF", pattern, BASE_DIR],
                capture_output=True,
                text=True,
            )
        else:
            result = subprocess.run(
                ["grep", "-rinE", pattern, BASE_DIR],
                capture_output=True,
                text=True,
            )
        return result.stdout if result.stdout else "No matches found."

    except Exception as e:
        return f"Error running grep: {str(e)}"


@tool
def find_file_path(filename: str) -> str:
    """
    Locates the full system path for a given filename starting from a search directory.
    Useful for finding configuration files, data scripts, or documents.
    Use this when you cannot find a file path.
    """

    for root, dirs, files in os.walk(Path(BASE_DIR).absolute().resolve()):
        if filename in files:
            return os.path.join(root, filename)

    return f"File '{filename}' not found in {os.path.abspath(BASE_DIR)}."


class FileReadChunksTool(BaseTool):
    name: str = "read_file_chunk"
    description: str = """
         Read a specific range of lines from a file. 
         This is your default tool in order to get more context if not searching for function definitions. 
         Use this when you want additional context around certain line numbers, such as around lines identified by grep_search where function calls happen to find where a variable comes from.
         Recommended to have a span of 100 lines above and below an area of interest.
         """
    base_dir: Path = Field(description="The root directory for file operations")

    def __init__(self, base_dir: Path):
        super().__init__(base_dir=base_dir.resolve())

    def _run(self, file_path: str, start: int, end: int):
        target = (self.base_dir / file_path).resolve()

        # Idk how this even happened, but it did.
        if isinstance(start, str):
            parts = start.split(",")
            start = int(parts[0].strip())
            end = int(parts[1].strip())

        if self.base_dir not in target.parents:
            return "Error: Access outside allowed directory."

        if not target.exists():
            return "Error: File does not exist."

        if target.is_dir():
            return f"Target {target} is a directory: Here is the directory listing:  {os.listdir(target.absolute().resolve())}"

        with open(target, "r") as f:
            if start > end:
                tmp = start
                start = end
                end = tmp
            lines = f.readlines()
            context = "".join(lines[start:end])
            return context if context else 'SYSTEM: Retry tool call. "done": false,'

    async def _arun(self, *args, **kwargs):
        raise NotImplementedError("Async not implemented.")


class FileReadTool(BaseTool):
    name: str = "read_file"
    description: str = (
        "Reads a file from the allowed codebase directory. "
        "Input must be a relative file path."
        "Use this sparingly to be efficient. Attempt to use the opengrep_search tool first, then try to load the file in chunks second."
    )
    base_dir: Path = Field(description="The root directory for file operations")

    def __init__(self, base_dir: Path):
        super().__init__(base_dir=base_dir.resolve())

    def _run(self, file_path: str):
        target = (self.base_dir / file_path).resolve()

        if self.base_dir not in target.parents:
            return "Error: Access outside allowed directory."

        if not target.exists():
            return "Error: File does not exist."

        return target.read_text(encoding="utf-8")

    async def _arun(self, *args, **kwargs):
        raise NotImplementedError("Async not implemented.")


class SitgrepAgent:
    def __init__(
        self,
        model: str = "qwen2.5-coder:14b",
        base_dir: Optional[str] = None,
        agent_endpoint: Optional[str] = None,
    ):

        global OLLAMA_URL
        global BASE_DIR

        if agent_endpoint:
            OLLAMA_URL = agent_endpoint
        else:
            OLLAMA_URL = "http://localhost:11434"

        self.model = model
        self.base_dir: Path = (
            Path(base_dir).resolve() if base_dir else Path(os.getcwd()).resolve()
        )

        self.tools: List[BaseTool] = []
       
        BASE_DIR = str(self.base_dir)

        self.tool_map = {
            "opengrep_search": opengrep_search,
            "grep_search": grep_search,
            "find_file_path": find_file_path,
        }

        self.add_tool(opengrep_search)
        self.add_tool(grep_search)
        self.add_tool(find_file_path)

        if self.base_dir:
            self.add_tool(FileReadTool(self.base_dir))
            self.add_tool(FileReadChunksTool(self.base_dir))
            self.tool_map["read_file"] = FileReadTool(self.base_dir)
            self.tool_map["read_file_chunk"] = FileReadChunksTool(self.base_dir)

        log.info(
            "AI analysis may take several hours. Please keep the device from sleeping during this to prevent the agent from hanging."
        )

    def initialize(self):

        # Create LLMs
        self.engineer_model = ChatOllama(
            model=self.model,
            temperature=0.1,
            num_ctx=32000,
            format="json",
            keep_alive="30m",
            
            # client_kwargs={"timeout": httpx.Timeout(25.0, connect=5.0)},
        )

        judge_llm = ChatOllama(
            model=self.model,
            temperature=0.0,
            num_ctx=20000,
            format="json",
        )

        self.judge_llm = judge_llm.with_structured_output(judge.JudgeResponse)

        # Initialize engineer agent
        self.engineer_agent = create_agent(
            model=self.engineer_model,
            system_prompt=engineer.SYSTEM_PROMPT,
        )

    def send(self, type: AgentType, message: str):
        MAX_RETIRES = 3
        for attempt in range(MAX_RETIRES):
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = None
                if type == AgentType.ENGINEER:
                    future = executor.submit(
                        self.engineer_agent.invoke,
                        {
                            "messages": [
                                SystemMessage(
                                    content="""Before providing a final answer, you must:
                                        - You MUST use at least 2 tool calls to analyze code before stopping
                                        - If a tool returns 'not found' or a small chunk, use another tool to search for the definition elsewhere.
                                        - You must end with your required response.
                                        - Perform a 'Self-Correction' step: Ask yourself, 'Is there any missing context that would make this vulnerability a false positive?'
                                        - Do not stop until you have traced the data flow from source to sink.
                                        - If further investigation is required, keep going.
                                        - Perform at LEAST 2 tools calls before stopping"""
                                ),
                                HumanMessage(
                                    content=f"Here is context and the history: {message}"
                                ),
                            ]
                        },
                        config={"recursion_limit": 100},
                    )
                elif type == AgentType.JUDGE:
                    future = executor.submit(
                        self.judge_llm.invoke,
                        [
                            ("system", judge.SYSTEM_PROMPT),
                            ("human", f"Here is the chat history: {message}"),
                        ],
                    )
                try:
                    return future.result(timeout=300)
                except concurrent.futures.TimeoutError:
                    # log.info(f"Agent timed out. Restarting agent and retrying ({attempt}/{MAX_RETIRES})...")
                    self.restart(True)
                    self.send(type, message)
        log.warn("Failed to get agent response after 3 attempts... continuing...", True)
        return {"messages": []}

    def add_tool(self, tool: BaseTool):
        self.tools.append(tool)

    def kill_ollama(self):
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                if proc.info["name"] and "ollama" in proc.info["name"].lower():
                    log.info(f"Killing agent PID {proc.pid}")
                    proc.kill()
                    return True

                # More reliable check:
                elif proc.info["cmdline"] and any(
                    "ollama" in arg.lower() for arg in proc.info["cmdline"]
                ):
                    log.info(f"Killing agent PID {proc.pid}")
                    proc.kill()
                    return True

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return False

    def __wait_for_ollama(self, timeout=60):
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                r = requests.get(OLLAMA_URL)
                if r.status_code == 200:
                    return True
            except requests.exceptions.ConnectionError:
                pass
            time.sleep(0.5)

        log.error("Could not connect to Ollama server", console, False)
        sys.exit(1)

    def __start_ollama(self):
        process = subprocess.Popen(
            ["ollama", "serve"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return process

    def stop(self):
        if hasattr(self, "process"):
            self.process.terminate()
            self.process.wait()
            return True
        elif self.kill_ollama():
            return True
        else:
            return False

    def restart(self, isRunning: bool):
        if self.stop():
            self.start(restart=isRunning)
        else:
            log.warn("Error stopping agent process")

    def start(self, restart=False):
        try:
            r = requests.get(OLLAMA_URL, timeout=1)
            if r.status_code != 200:
                raise Exception

            self.restart(isRunning=False)
            
        except Exception:
            self.process = self.__start_ollama()
            self.__wait_for_ollama()
            
            if not restart:
                log.info("Ollama started...")
                model_list = subprocess.run(
                    ["ollama", "list"], capture_output=True, text=True
                )

                if self.model not in model_list.stdout:

                    log.info("Pulling agent model...")
                    output = subprocess.run(
                        ["ollama", "pull", self.model], stdout=subprocess.PIPE, text=True
                    )
                    if getattr(output, "stderr", None) and output.stderr and "requires a newer version of Ollama" in output.stderr:
                        log.error(
                            f"Ollama returned the following error: {output.stderr}",
                            console,
                            False,
                        )
                        sys.exit(1)

                    log.info("Model downloaded...")
            self.initialize()

