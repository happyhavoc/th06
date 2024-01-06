import argparse
import itertools
import string
import subprocess
import sys

parser = argparse.ArgumentParser(
    prog="gendef", description="Generate .def file based on the provided object files."
)
parser.add_argument(
    "-o", "--output", action="store", help="File to store the generated stubs in"
)
parser.add_argument("input", nargs="+", help="File to store the generated stubs in")
args = parser.parse_args()

f = open(args.output, "w")
print("EXPORTS", file=f)

for arg in args.input:
    out = subprocess.check_output(["dumpbin", "/HEADERS", "/SYMBOLS", arg])

    # First, find the appropriate section
    cur_section = None
    text_sections = []
    for line in out.split(b"\n"):
        if line.startswith(b"SECTION HEADER #"):
            cur_section = int(line[len("SECTION HEADER #") :], 16)
        if b".text" in line:
            text_sections.append(cur_section)

    if len(text_sections) == 0:
        print("WARNING: Failed to find .text in object file " + arg, file=sys.stderr)

    for line in out.split(b"\n"):
        line = str(line, "utf8")
        if "External" in line:
            sect_idx = line.find("SECT")

            def ishexdigit(c):
                return c in string.hexdigits

            if sect_idx == -1:
                continue
            sect_int = int(
                "".join(
                    itertools.takewhile(ishexdigit, line[sect_idx + len("SECT") :])
                ),
                16,
            )
            if sect_int in text_sections:
                symbols = line.split("| ")[1].strip()
                symbols = symbols.split(" ", 1)
                if len(symbols) > 1:
                    mangled_symbol, demangled_symbol = symbols
                else:
                    mangled_symbol = symbols[0]
                    demangled_symbol = ""
                print("    " + mangled_symbol + " PRIVATE", file=f)
