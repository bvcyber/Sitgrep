import os
import shutil
from utils.progressbar import ProgressBar
import yaml
import sys
import json
import git
import getpass
from utils import messages as msg
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn
from rich.traceback import install
install(show_locals=True)
console = Console(color_system="truecolor")

USER_HOME = os.path.expanduser(f"~{getpass.getuser()}")
LOCAL_FILES = f"{USER_HOME}/.sitgrep"
LOCAL_RULES = f"{LOCAL_FILES}/rules/"
SOURCES_PATH = os.path.join(LOCAL_FILES, "config", "sources.json")
SOURCES_BAK_PATH = os.path.join(LOCAL_FILES, "config", ".sources.json")

def hsv_to_rgb(h, s, v):
    """Converts HSV to RGB."""
    if s == 0.0:
        return int(v * 255), int(v * 255), int(v * 255)

    i = int(h * 6.0)
    f = (h * 6.0) - i
    p, q, t = (
        int(255 * (v * (1.0 - s))),
        int(255 * (v * (1.0 - s * f))),
        int(255 * (v * (1.0 - s * (1.0 - f)))),
    )
    v = int(v * 255)
    i %= 6

    if i == 0:
        return v, t, p
    if i == 1:
        return q, v, p
    if i == 2:
        return p, v, t
    if i == 3:
        return p, q, v
    if i == 4:
        return t, p, v
    if i == 5:
        return v, p, q

def rgb_to_hex(rgb):
    """Converts RGB to a hex color code."""
    return "#{:02X}{:02X}{:02X}".format(rgb[0], rgb[1], rgb[2])

def src_json(src):
    return {"sources": src}

def get_sources(path = SOURCES_PATH) -> list:

    try:
        sources = []
        with open(path, "r") as f:
            sources = json.load(f)["sources"]
        return sources
    except FileNotFoundError:
        print("sources.json not found.")
        return sources
    except json.JSONDecodeError:
        print("sources.json is not valid JSON.")
        return sources


class SourceHandler:

    def __init__(self):
        self.origin = LOCAL_FILES
        self.excluded_folders = []
        self.clone_progress = ProgressBar(target="rule repository")
    
    def add_source(self, args):
        msg.info(f"Adding source, name: {args.name}, url: {args.url}")
        
        new_src = {}
        new_src["name"] = args.name
        new_src["url"] = args.url

        sources = get_sources()
        sources.append(new_src)

        with open(SOURCES_PATH, "w") as f:
            json.dump(src_json(sources), f, indent=2)
        
        sys.exit(0)

    def delete_source(self, args):
        msg.info(f"Deleting source, name: {args.name}")

        sources = get_sources()

        for index, source in enumerate(sources):
            if source["name"] == args.name:
                del sources[index]
                break
        
        with open(SOURCES_PATH, "w") as f:
            json.dump(src_json(sources), f, indent=2)

        sys.exit(0)

    def restore_sources(self, args):
        msg.info(f"Restoring original sources")
        sources = get_sources(SOURCES_BAK_PATH)
        with open(SOURCES_PATH, "w") as f:
            json.dump(src_json(sources), f, indent=2)

        sys.exit(0)

    def list_sources(self, args):
        sources = get_sources()
        print(json.dumps(sources, indent=2))
        sys.exit(0)

    def exclude_folders(self, directory, excluded_folders):
        """Excludes specific folders from a directory."""
        return [f for f in os.listdir(directory) if f not in excluded_folders]

    def download_git_repo(self, url, dest):
        """Downloads the Semgrep rules repository."""
        self.repo_dest = os.path.join(LOCAL_FILES, "rules", dest)
        self.repo_url = url

        try:
            if os.path.exists(self.repo_dest):
                shutil.rmtree(self.repo_dest)
                
            git.Repo.clone_from(self.repo_url, self.repo_dest, branch=None, progress=self.clone_progress)   # type: ignore
  
            msg.info(f"Repository cloned successfully to {self.repo_dest}")
            return 0

        except git.GitCommandError as e:
            print()
            msg.error(f"Error cloning repository: ", console)
            sys.exit(1)
        except Exception as e:
            print()
            msg.error(f"Error cloning repository: ", console)
            sys.exit(1) 

    def is_valid_yaml_file(self, file_path):
        """Checks if a YAML file is valid based on certain rules."""
        if ".test" in file_path:
            return False

        try:
            with open(file_path, "r") as file:
                data = yaml.safe_load(file)
                for rule in data["rules"]:
                    if "id" in rule:
                        if rule["id"] in [
                            "package-dependencies-check",
                            "detected-aws-access-key-id-value",
                            "detected-aws-account-id",
                            "no-scriptlets",
                            "aws-access-token",
                            "use-escapexml",
                            "use-jstl-escaping",
                            "generic-api-key",
                            "html-in-template-string",
                            "var-in-script-tag"
                        ]:
                            return False
                    if "metadata" in rule:
                        if "category" in rule["metadata"]:
                            if rule["metadata"]["category"] not in [
                                "security",
                                "audit",
                            ]:
                                return False
                            if (
                                "rule has been deprecated" in rule["message"]
                                or "rule is deprecated" in rule["message"]
                            ):
                                return False
                        else:
                            return False
                        for key in ["confidence", "impact", "likelihood"] :
                            if key not in rule["metadata"] and "owasp-mobile" not in rule["metadata"]:
                                return False
                    else:
                        return False
            return True
        except Exception:
            return False

    def count_files(self, directory):
        """Counts the number of files in a directory recursively."""
        file_count = 0
        for root, dirs, files in os.walk(directory):
            file_count += len(files)
        return file_count

    def prune_files(self, directory):
        """Prunes unnecessary files from the repository."""
        count = 0
        progress = 0
        total = self.count_files(directory)  # Assuming this method gives the total number of files

        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:.2f}%",
            transient=True  # Makes the progress bar disappear once done
        ) as progress_bar:
            task = progress_bar.add_task("Pruning files", total=total)

            # Loop through the files in the directory
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    if file_path.endswith((".yaml", ".yml")):
                        if not self.is_valid_yaml_file(file_path):
                            os.remove(file_path)
                            count += 1
                    else:
                        os.remove(file_path)
                        count += 1
                    
                    progress += 1
                    # Update the progress bar
                    progress_bar.update(task, completed=progress)

            # Optionally remove the .github directory if it exists
            if os.path.exists(f"{directory}.github"):
                shutil.rmtree(f"{directory}.github")
                
        # print(f"\nPruned {count} files")
        # print(f"Kept {total - count} files")

    def organize_rules(self, directory):
        """Organizes the rules by their language."""
        count = 0
        for root, _, files in os.walk(directory):
            for yaml_file in [
                f for f in files if f.endswith(".yaml") or f.endswith(".yml")
            ]:
                file_path = os.path.join(root, yaml_file)
                with open(file_path, "r") as file:
                    semgrep_rules = yaml.safe_load(file)

                for rule in semgrep_rules.get("rules", []):
                    languages = rule.get("languages", [])
                    if not languages:
                        continue

                    language_dir = f"{self.repo_dest}/{languages[0]}"
                    if not os.path.exists(language_dir):
                        os.makedirs(language_dir)

                    rule_id = rule["id"]
                    rule_file = os.path.join(language_dir, f"{rule_id}.yaml")

                    with open(rule_file, "w") as rule_output_file:
                        yaml.dump({"rules": [rule]}, rule_output_file)
                        count += 1

        # msg.info(f"Organized {count} files")
        shutil.rmtree(directory)

    def fetch_sources(self, args):
        """Runs the complete process: cloning, organizing, pruning."""
        try:
            for repo in get_sources():
                status = self.download_git_repo(repo["url"], repo["name"])
                try:
                    if status == 0 and repo["url"] == "https://github.com/semgrep/semgrep-rules":
                        if os.path.isdir(self.repo_dest + "/contrib/"):
                            self.organize_rules(self.repo_dest + "/contrib/")

                        if os.path.isdir(self.repo_dest + "/problem-based-packs/"):
                            self.organize_rules(self.repo_dest + "/problem-based-packs/")

                    self.prune_files(self.repo_dest)

                except Exception as e:
                    msg.error(f"Error while pruning rule repository: ", console )
                    sys.exit(1)
            sys.exit(0)

        except Exception as e:
            msg.error(f"Error while cloning rule repository: ", console )
            sys.exit(1)

   