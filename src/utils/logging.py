# RED = "\033[91m"
# GREEN = "\033[92m"
# YELLOW = "\033[93m"
# CYAN = "\033[96m"
# RESET = "\033[0m"
# ORANGE = "\033[38;5;208m"

from rich.console import Console
from datetime import datetime

console = Console()


def time() -> str:
    return datetime.now().strftime("%H:%M:%S")


def error(msg, console, showException=True):
    console.print(f"\n[{time()}][[red]ERROR[/]] {msg} ")
    if showException:
        console.print_exception(show_locals=False)


def get_info(msg):
    return f"[{time()}][[cyan]INFO[/]] {msg}"


def get_error(msg):
    return f"[{time()}][[red]ERROR[/]] {msg}"


def get_success(msg):
    return f"[{time()}][[green]SUCCESS[/]] {msg}"


def get_warn(msg):
    return f"[{time()}][[yellow]WARN[/]] {msg}"


def success(msg):
    console.print(f"[{time()}][[green]SUCCESS[/]] {msg}")


def debug(msg):
    console.print(f"\n[{time()}][[orange1]DEBUG[/]] {msg}")


def info(msg):
    console.print(f"[{time()}][[cyan]INFO[/]] {msg}")


def progress_bar(msg, bar, percent: float, count=""):
    console.print(
        f"[{time()}][[cyan]INFO][/] {msg}: |{bar}[RESET]| {percent:.2f}% | {count}",
        end="\r",
    )


def progress(msg):
    console.print(f"[{time()}][[cyan]INFO[/]] {msg}", end="\r")


def warn(msg):
    console.print(f"\n[{time()}][[yellow]WARN[/]] {msg}")
