<div align="center">

  <img src="https://github.com/bvcyber.png" alt="Bureau Veritas" width="64" />


  ![HTML Screenshot](assets/sitgrep-slogan.png)
  
  # Sitgrep

  > Enhance your code review.

  [![License](https://img.shields.io/badge/license-GNU--LGPL--v3-green)](LICENSE)
  [![Status](https://img.shields.io/badge/status-active-brightgreen.svg)]()

  [Docs](#) · [Report an Issue](issues)

</div>

---

Sitgrep is a wrapper for [Opengrep](https://github.com/opengrep/opengrep) that makes it quick and easy to scan code for insecure coding practices and hard-coded secrets. Additionally, Sitgrep provides an agentic review of findings to pre-triage findings for you. 

Sitgrep offers an intuitive solution for scanning GitHub and GitLab repositories. By simply providing a link to any repository, Sitgrep will automatically download and perform a thorough scan, streamlining the process for reviewing code for security issues. It then generates a results page, which gets automatically opened, allowing you to review findings quicker and export results for your client, saving you precious time while on your engagement. Additionally, this can be used locally without sending metrics which makes it viable for scanning proprietary code that is not public, making it perfect for when clients are a bit reluctant to run a static analysis tool on their code base.

![HTML Screenshot](assets/dashboard.png)
![HTML Screenshot](assets/findings.png)


# Installation

## Linux/WSL and MacOS

1. Download the latest release from the releases page
2. Unzip the project and navigate to it in the terminal.
  - Optionally, create a virtual environment and activate it:
    ``` 
    python3 -m venv sitgrep_venv && source sitgrep_venv/bin/activate
    ```
3. Install the requirements:
    ```
    python3 -m pip install -r requirements.txt
    ```
4. Run the install script: 
   ```
    python3 install.py
    ```
5. Run the rule fetcher:
    ```
    sitgrep sources fetch
    ```

## Docker

The Docker usage is only meant for instances where Sitgrep cannot run natively in a UNIX enviroment like Linux/WSL or MacOS. As such, it is limited to default scan settings without being able to supply any CLI arguments. 

1. Download the latest release from the releases page
2. Unzip the project and navigate to it in the terminal.
3. Run the following command to build the Docker image:
    ```
    docker build -t sitgrep .
    ```
4. Set the following environment variable to the folder containing the code to scan:
    ```
    HOST_DIRECTORY=/home/User/path/to/code
    ```
5. Run the following docker command to start the container (you can alias this for future use):
    ```
    docker run -p 127.0.0.1:9000:9000 -e HOST_DIRECTORY="${HOST_DIRECTORY}" -v "${HOST_DIRECTORY}:/target/" sitgrep
    ```
6. Go to 127.0.0.1:9000 in the web browser to access the web UI.
7. Confirm that the directory to scan is correct and click the `Scan` button.
8. The scan will begin and run inside the docker container. Once complete, a ZIP folder with the results will automtically be downloaded.

# Uninstall
If you want to uninstall, simply run the following command:

```
python3 -m pip uninstall sitgrep
```

# Usage
```
sitgrep {local,sources} [-h] [-c CONTEXT] [-d DIRECTORY] [-o OUTPUT] [-n Download_Only] 

Example: sitgrep -c 2 -d ~/my/dir/ -o output_file 

positional arguments:
  local                           Enable local mode
    -N, --no-scan                 Only download the packages, do not scan them. (default=False)

  sources             Manage sources
    add                 Add a source
    delete              Delete a source
    list                List all sources
    restore             Restore original sources
    fetch               Fetch all sources
    export              Export rules to ZIP file

optional arguments:
  -h, --help          Show this help message and exit
  -c, --context       The amount of context lines above and below to save (default=5)
  -d, --directory     The directory to scan (default=CWD)
  -o, --output        The output file name
  -V, --version       Print Sitgrep's version   
  -v, --verbose       Increase verbosity level (default 0, max of 3)
  -j, --json-input    Load a Opengrep JSON output file
  -n, --no-auto-open Disable auto-opening the results in the browser
  -gh, --github       Provide a list of Github repositories to download and scan. Overrides the directory parameter (-d)
  -gl, --gitlab       Provide a list of Gitlab repositories to download and scan. Overrides the directory parameter (-d)
  -jf, --jar_file     Provide the path to a JAR file. The file will be decompiled and resulting source code scanned. Relative and absolute paths are supported.
  -vs, --vscode       Open the folder being scanned in VSCode after scan finishes. Only usable when not using --github or --gitlab
  -i, --ssh-key       Specify an SSH key to use
  -p, --protocol      Specify SSH or HTTPS when cloning git repositories
  -ai, --agent        Enable AI triaging after scan finishes
  -l, --model         Specify the Ollama model to use for local instances
  -ae, --agent-endpoint Specify the Ollama server endpoint
```

1. Run the command `sitgrep` in the terminal with any additional arguments as needed.
2. Go to the `sitgrep-results` folder that the tool automatically makes. 
3. Open the HTML page that Sitgrep generates.
4. Verify all findings. Results should not be taken at face-value.
5. In the HTML page created by Sitgrep, delete any false-positives.
6. Optional: Export triaged results in JSON format
    * Exporting exports all findings that are not deleted. Findings that are hidden by the filter are also included.

## Agentic Review
Sitgrep provides an agentic AI review of findings to identify false positives. Don't worry, the results will simply be marked by the AI with it's decision and reasoning. It won't just delete them altogether, resulting in false negatives. 

*NOTE*: This feature may take several hours to complete, depending on how many findings. You will want to keep the device from sleeping during this to prevent the agent from hanging. 

### Requirements
- It is recommended to have the equivelant of the following to use agentic review:
  - M-series chip Mac with at least 32GB of RAM
  - 14–16 GB VRAM for dedicated GPUs

### Features
- Choose from several different models to run locally to be catered to your hardware's capabilities (smaller models will have worse results)
- Choose an Ollama server location to allow dedicated Ollama servers to handle processing of data to bypass local hardware capabilities

## Source Management
Sitgrep offers a way to dynamically add, delete, and list rule sources:

AddSource - Adds a new rule source by specifying a name/ID, URL, and categories for the source repository. Leave URL blank if manually placed into `~/.sitgrep/rules/`
```
sitgrep sources add --id <id> --url <repo_url> --categories <categories>
```

DeleteSource - Deletes a rule source with a given name/ID
```
sitgrep sources delete --id <id>
```

ListSources - List all rule sources
```
sitgrep sources list
```

RestoreSources - Restore the original rule source list
```
sitgrep sources restore
```

ExportSources - Export all currently downloaded rules to a ZIP file
```
sitgrep sources export --output <file_path>
```

# Github and Gitlab Packages

``--github/-g`` can be used for Github packages in both ``local`` mode and normal mode. Usage matches the ``a`` flag, which the details of can be found below.

# Local Mode

`sitgrep local` should be used for all local scans, as this uses local rules, sourced from Semgrep's open source rules github, instead of Semgrep's official registry.

`sitgrep local --github/--gitlab` downloads the packages, listed in a text file or in the command line:

```sitgrep local --github/--gitlab list.txt ```

or

```sitgrep local --github/--gitlab Package1,Package2 ```

Note: `--github/--gitlab` overrides the `-d/--directory` parameter


### How to create list.txt?
The `--github/--gitlab` parameter looks for a text file or a list of Github/Gitlab URLs. 

### Don't want to scan? Only want to download the packages?

No problem! Use the `-N/--no-scan` flag to only download the repositories without scanning them.


# Troubleshooting
Oh no, I am have issues installing or running Sitgrep! What's wrong!?

Here are some possible issues:

* Install works, Sitgrep command not found:

  * Check if your PATH includes where Sitgrep is installed. To check, either rerun the installer and look for a WARNING message, or run `pip/pip3 show sitgrep`. If your PATH does not include the install location, you will need to update your PATH to include the install location

* Install works, Sitgrep returns with errors:

  * A case with Semgrep using too much memory can cause Sitgrep to fail. The cause of this is due to using a generic rules having excessively broad pattern matching using the `generic` language type. The solution is to specify the exact supported languages.

  * Sometimes Semgrep itself will return segfaults. It will look like `<Signals.SIGSEGV: 11>`. A solution to this is simply removing Semgrep and reinstalling. You can use the installer, the requirements.txt, or manually reinstall Semgrep. 


For any issues that aren't resolved by these potential fixes, please open an issue on Sitgrep's Github page.

# Contributing
If contributing Semgrep rules, please use Semgrep's rule playground to write and test the rules before submitting them to Sitgrep.

## Adding Your Own Rules
If you want to add your own rules, put them in the `~/.sitgrep/rules/local/` folder

# Acknowledgment

- Opengrep: [Semgrep](https://github.com/opengrep/opengrep)
- Semgrep rules: [Semgrep rules registry](https://github.com/semgrep/semgrep-rules) by Semgrep
- Android rules: [MindedSecurity rules registry](https://github.com/mindedsecurity/semgrep-rules-android-security) by IMQ Minded Security
- Mobile rules: [insideapp-oss rules registry](https://github.com/insideapp-oss/mobile-application-security-rules) by insideapp-oss

---

<div align="center">

  Maintained by [John Ascher](https://github.com/S0meday) @ [Bureau Veritas](https://cybersecurity.bureauveritas.com/)

</div>
