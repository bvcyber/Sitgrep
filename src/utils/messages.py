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
    console.print(f"[[red]ERROR[/]] {msg} ")
    if showException:
        console.print_exception(show_locals=False)


def get_info(msg):
    return f"[[cyan]INFO[/]] {msg}"


def get_error(msg):
    return f"[[red]ERROR[/]] {msg}"


def get_success(msg):
    return f"[[green]SUCCESS[/]] {msg}"


def get_warn(msg):
    return f"[[yellow]WARN[/]] {msg}"


def success(msg):
    console.print(f"[[green]SUCCESS[/]] {msg}")


def debug(msg):
    console.print(f"[[orange1]DEBUG[/]] {msg}")


def info(msg):
    console.print(f"[[cyan]INFO[/]] {msg}")


def progress_bar(msg, bar, percent: float, count=""):
    def percentage_to_color(percentage):
        percentage = max(0, min(100, percentage))
        r = int(255 * (100 - percentage) / 100)
        g = int(230 * percentage / 100)
        b = 0

        return f"\033[38;2;{r};{g};{b}m"

    console.print(
        f"[[cyan]INFO][/] {msg}: |{percentage_to_color(percent)}{bar}[RESET]| {percent:.2f}% | {count}",
        end="\r",
    )


def progress(msg):
    console.print(f"[[cyan]INFO[/]] {msg}", end="\r")


def warn(msg):
    console.print(f"[[yellow]WARN[/]] {msg}")
