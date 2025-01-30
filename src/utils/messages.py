RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
ORANGE = "\033[38;5;208m"


def error(msg):
    print( f"[{RED}ERROR{RESET}] {msg}")

def get_info(msg):
    return f"[{CYAN}INFO{RESET}] {msg}"

def get_error(msg):
    return f"[{RED}ERROR{RESET}] {msg}"

def get_success(msg):
    return( f"[{GREEN}SUCCESS{RESET}] {msg}")

def get_warn(msg):
    return( f"[{YELLOW}WARN{RESET}] {msg}")

def success(msg):
    print( f"[{GREEN}SUCCESS{RESET}] {msg}")

def debug(msg):
    print( f"[{ORANGE}DEBUG{RESET}] {msg}")

def info(msg):
    print(f"[{CYAN}INFO{RESET}] {msg}")

def progress_bar(msg, bar, percent: float, count=""):
    def percentage_to_color(percentage):
        percentage = max(0, min(100, percentage))
        r = int(255 * (100 - percentage) / 100)
        g = int(230 * percentage / 100)
        b = 0

        return f"\033[38;2;{r};{g};{b}m"

    print(f"[{CYAN}INFO{RESET}] {msg}: |{percentage_to_color(percent)}{bar}{RESET}| {percent:.2f}% | {count}",end="\r")

def progress(msg):
    print(f"[{CYAN}INFO{RESET}] {msg}", end="\r")
   
def warn(msg):
    print(f"[{YELLOW}WARN{RESET}] {msg}")

