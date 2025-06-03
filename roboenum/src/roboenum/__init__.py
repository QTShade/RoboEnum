import os

with open(f"{os.path.dirname(__file__)}/VERSION") as f:
    __version__ = f.read().strip()
