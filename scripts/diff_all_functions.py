#!/usr/bin/env python

import argparse
import csv
from pathlib import Path
import subprocess
import sys
import traceback

from generate_function_diff import (
    generate_function_diff_objdiff,
    generate_function_diff_satsuki,
)


def main():
    parser = argparse.ArgumentParser(
        prog="diff_all_functions",
        description="Generate a diff report of all implemented functions.",
    )
    parser.add_argument(
        "--diff-method",
        action="store",
        choices=["satsuki", "objdiff"],
        default="satsuki",
        help="Which program to use to generate the diff.",
    )
    args = parser.parse_args()

    base_dir = Path(__file__).parent.parent
    config_dir = base_dir / "config"

    implemented_csv = config_dir / "implemented.csv"

    success = True

    with open(implemented_csv) as f:
        vals = []
        for row in csv.reader(f):
            try:
                if args.diff_method == "satsuki":
                    left, right, diff, ratio = generate_function_diff_satsuki(row[0])
                else:
                    left, right, diff, ratio = generate_function_diff_objdiff(row[0])
                vals.append(
                    {
                        "name": row[0],
                        "diff": diff,
                        "ratio": ratio,
                    }
                )
            except subprocess.CalledProcessError as e:
                success = False
                if e.stderr is not None:
                    vals.append(
                        {"name": row[0], "error": str(e.stderr, "utf8").strip()}
                    )
                else:
                    vals.append({"name": row[0], "error": "failed"})
            except Exception as e:
                vals.append(
                    {
                        "name": row[0],
                        "error": "".join(
                            traceback.format_exception(None, e, e.__traceback__)
                        ),
                    }
                )

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
