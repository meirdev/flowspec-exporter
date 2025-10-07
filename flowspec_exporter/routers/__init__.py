import os
from pathlib import Path

DIR = Path(__file__).absolute().parent.parent

os.environ["NTC_TEMPLATES_DIR"] = str(DIR / "templates")
