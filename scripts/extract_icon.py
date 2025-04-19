import icon_extractor
from pathlib import Path
import sys
import os
import argparse


SCRIPT_PATH = Path(os.path.realpath(__file__)).parent
RESOURCES_PATH = SCRIPT_PATH.parent / "resources"
FILENAME = RESOURCES_PATH / "game.exe"


parser = argparse.ArgumentParser(
    prog="extract_icon", description="Extract the original icon from the game."
)
parser.add_argument(
    "-o", "--output", required=True, help="Path to write the extracted icon"
)
args = parser.parse_args()

if not FILENAME.exists():
    sys.stderr.write(
        "extract_icon.py: 'game.exe' not found. Copy your executable of Touhou 06 to 'resources/game.exe'"
    )
    sys.exit(1)
icon = icon_extractor.ExtractIcon(str(FILENAME))

with open(str(args.output), "wb") as icon_file:
    entries = icon.get_group_icons()
    icon_file.write(icon.export_raw(entries[0], 0))
