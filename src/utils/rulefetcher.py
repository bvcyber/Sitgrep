import os
import shutil
from utils.progressbar import ProgressBar
import yaml
import sys
import importlib
import git
import getpass
from utils import messages as msg
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn

user_home = os.path.expanduser(f"~{getpass.getuser()}")
local_files = f"{user_home}/.sitgrep"
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


class RuleFetcher:

        
    def __init__(self):
        self.repo_url = "https://github.com/semgrep/semgrep-rules"
        self.origin = local_files
        self.repo_dest = os.path.join(self.origin, "rules/semgrep")
        self.excluded_folders = []
        self.clone_progress = ProgressBar(target="rule repository")

    def exclude_folders(self, directory, excluded_folders):
        """Excludes specific folders from a directory."""
        return [f for f in os.listdir(directory) if f not in excluded_folders]

    def download_git_repo(self):
        """Downloads the Semgrep rules repository."""
        try:
            if not os.path.exists(self.repo_dest):
                os.mkdir(self.repo_dest)
            shutil.rmtree(self.repo_dest)
            git.Repo.clone_from(self.repo_url, self.repo_dest, branch=None, progress=self.clone_progress)   # type: ignore
  
            msg.info(f"Repository cloned successfully to {self.repo_dest}")
            return 0

        except git.GitCommandError as e:
            print()
            msg.error(f"Error cloning repository: {e}")
            sys.exit(1)
        except Exception as e:
            print()
            msg.error(f"Error cloning repository: {e}")
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
                        for key in ["confidence", "impact", "likelihood"]:
                            if key not in rule["metadata"]:
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

    def run(self):
        """Runs the complete process: cloning, organizing, pruning."""
        try:
            status = self.download_git_repo()
        except Exception as e:
            msg.error(f"Error while cloning rule repository: {e}")
            sys.exit(1)

        if status == 0:
            if os.path.isdir(self.repo_dest + "/contrib/"):
                self.organize_rules(self.repo_dest + "/contrib/")

            if os.path.isdir(self.repo_dest + "/problem-based-packs/"):
                self.organize_rules(self.repo_dest + "/problem-based-packs/")

            self.prune_files(self.repo_dest)
        else:
            msg.error("Git clone failed")
            sys.exit(1)
