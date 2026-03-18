import importlib
from typing import Callable
from git import RemoteProgress
from rich.console import Console
from utils import logging as log
from rich.progress import Progress, BarColumn, TextColumn

console = Console()


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
        self.log = f"Cloning {target}"
        self.task = self.progress.add_task(self.log, total=100)
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
                self.task, completed=cur_count, total=max_count, description=self.log
            )

    def finish(self):
        """Finish the progress bar manually if needed."""
        if self.task and self.progress:
            self.progress.stop()

    def stop(self):
        self.progress.stop()
