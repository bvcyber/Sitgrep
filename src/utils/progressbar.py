
from utils import messages as msg
import importlib
from git import RemoteProgress
from rich.progress import Progress, BarColumn, TextColumn
from rich.console import Console

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
    def __init__(self, target="", hide=True, *args, **kwargs):
        super().__init__(*args, **kwargs)
  
        self.progress = Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:.2f}%",
            transient=hide
        )
        self.msg = f"Cloning {target}"
        self.task = self.progress.add_task(self.msg, total=100)
        self.progress.start()
        self.total_progress = 0 
        self.total_max = 0  
        self.count = 0

    def update(self, op_code, cur_count, max_count=None, message=''):
        if max_count:

            if self.total_max != max_count:
                self.total_max = max_count
        
            self.progress.update(self.task, completed=cur_count, total=max_count, description=self.msg)

            if cur_count == self.total_max and self.count >= 4:
                self.progress.stop()
            elif cur_count == self.total_max:
                self.count += 1
         


    def finish(self):
        """Finish the progress bar manually if needed."""
        if self.task and self.progress:
            self.progress.stop() 


