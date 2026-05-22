# RED = "\033[91m"
# GREEN = "\033[92m"
# YELLOW = "\033[93m"
# CYAN = "\033[96m"
# RESET = "\033[0m"
# ORANGE = "\033[38;5;208m"

from rich.console import Console
from rich.markup import escape
from datetime import datetime

console = Console()


def time() -> str:
    return datetime.now().strftime("%H:%M:%S")


def error(msg, console, showException=True):
    console.print(f"\n[{time()}][[red]ERROR[/]] {escape(str(msg))} ")
    if showException:
        console.print_exception(show_locals=False)


def get_info(msg):
    return f"[{time()}][[cyan]INFO[/]] {escape(str(msg))}"


def get_error(msg):
    return f"[{time()}][[red]ERROR[/]] {escape(str(msg))}"


def get_success(msg):
    return f"[{time()}][[green]SUCCESS[/]] {escape(str(msg))}"


def get_warn(msg):
    return f"[{time()}][[yellow]WARN[/]] {escape(str(msg))}"


def success(msg):
    console.print(f"[{time()}][[green]SUCCESS[/]] {escape(str(msg))}")


def debug(msg):
    console.print(f"\n[{time()}][[orange1]DEBUG[/]] {escape(str(msg))}")


def info(msg):
    console.print(f"[{time()}][[cyan]INFO[/]] {escape(str(msg))}")


def progress_bar(msg, bar, percent: float, count=""):
    console.print(
        f"[{time()}][[cyan]INFO][/] {escape(str(msg))}: |{bar}[RESET]| {percent:.2f}% | {count}",
        end="\r",
    )


def progress(msg):
    console.print(f"[{time()}][[cyan]INFO[/]] {escape(str(msg))}", end="\r")


def warn(msg, newline = False):
    if newline:
        console.print(f"\n[{time()}][[yellow]WARN[/]] {escape(str(msg))}")
    else:
        console.print(f"[{time()}][[yellow]WARN[/]] {escape(str(msg))}")
