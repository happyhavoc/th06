#!/usr/bin/env python

import csv
import difflib
from pathlib import Path
import subprocess
import sys

from generate_function_diff import generate_function_diff


def main():
    base_dir = Path(__file__).parent.parent
    config_dir = base_dir / "config"

    implemented_csv = config_dir / "implemented.csv"

    success = True

    with open(implemented_csv) as f:
        vals = []
        for row in csv.reader(f):
            try:
                orig, reimpl = generate_function_diff(row[0])
                ratio = difflib.SequenceMatcher(None, orig, reimpl).ratio()
                diff = "\n".join(
                    difflib.unified_diff(
                        orig.split("\n"),
                        reimpl.split("\n"),
                        "Original",
                        "Reimplementation",
                        lineterm="",
                    )
                )
                vals.append(
                    {
                        "name": row[0],
                        "diff": diff,
                        "ratio": ratio,
                    }
                )
            except subprocess.CalledProcessError as e:
                success = False
                vals.append({"name": row[0], "error": str(e.stderr, "utf8").strip()})

        print("# Report")
        print("")
        print("name | result")
        print("-----|-------")
        for val in vals:
            name = val["name"]
            id = val["name"].lower().replace(":", "__")
            if "error" in val:
                name = f"[{name}](#user-content-{id})"
                sys.stdout.flush()
                sys.stdout.buffer.write(f"{name} | 💥\n".encode("utf8"))
            else:
                if val["ratio"] != 1:
                    name = f"[{name}](#user-content-{id})"
                print(f"{name} | {val['ratio'] * 100:.2f}%")

        for val in vals:
            if "error" not in val and val["ratio"] == 1:
                # 100% matching, nothing to see here.
                continue

            print("")
            print("")
            id = val["name"].lower().replace(":", "__")
            print(f'<details id="{id}"><summary><h2>{val["name"]}</h2></summary>')
            print("")
            if "error" in val:
                print("Failed to generate diff:")
                print(val["error"])
            elif val["ratio"] != 1:
                print("```diff")
                print(val["diff"])
                print("```")
            print("")
            print("</details>")

    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
