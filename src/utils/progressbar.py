import importlib
from typing import Callable
from git import RemoteProgress
from rich.console import Console
from utils import messages as msg
from rich.progress import Progress, BarColumn, TextColumn

console = Console()


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


class ProgressBar(RemoteProgress):
    OP_CODES = [
        "BEGIN",
        "CHECKING_OUT",
        "COMPRESSING",
        "COUNTING",
        "END",
        "FINDING_SOURCES",
        "RECEIVING",
        "RESOLVING",
        "WRITING",
    ]

    OP_CODE_MAP = {getattr(RemoteProgress, _op_code): _op_code for _op_code in OP_CODES}

    def __init__(self, target="", hide=True, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.progress = Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:.2f}%",
            transient=hide,
            console=console,
        )
        self.msg = f"Cloning {target}"
        self.task = self.progress.add_task(self.msg, total=100)
        self.total_progress = 0
        self.total_max = 0
        self.count = 0

    @classmethod
    def get_curr_op(cls, op_code: int) -> str:
        """Get OP name from OP code."""
        # Remove BEGIN- and END-flag and get op name
        op_code_masked = op_code & cls.OP_MASK
        return cls.OP_CODE_MAP.get(op_code_masked, "?").title()

    def start(self):
        self.progress.start()

    def update(self, op_code, cur_count, max_count=None, message=""):
        if max_count:

            if self.total_max != max_count:
                self.total_max = max_count

            self.progress.update(
                self.task, completed=cur_count, total=max_count, description=self.msg
            )

    def finish(self):
        """Finish the progress bar manually if needed."""
        if self.task and self.progress:
            self.progress.stop()

    def stop(self):
        self.progress.stop()
