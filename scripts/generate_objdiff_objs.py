import coff
from pathlib import Path
import re
import struct
import sys

SCRIPTS_DIR = Path(__file__).parent


def demangle_msvc(sym):
    offset = 0
    if len(sym) == offset or sym[offset : offset + 1] != b"?":
        # Unmangled symbol?
        return sym
    offset += 1

    # Read name. Start with special symbols
    special = None
    name = None
    if sym[offset : offset + 1] == b"?" and sym[offset + 1 : offset + 2].isdigit():
        # Special symbol.
        special = sym[offset + 1] - ord("0")
        offset += 2
    else:
        # Read a normal name.
        start_of_name = offset
        end_of_name = sym.find(b"@", offset)
        if end_of_name == -1:
            end_of_name = len(sym)
            offset = len(sym)
        else:
            offset = end_of_name + 1
        name = sym[start_of_name:end_of_name]

    # Read scope
    start_of_scope = offset
    end_of_scope = sym.find(b"@", offset)
    if end_of_scope == -1:
        end_of_scope = len(sym)
        offset = len(sym)
    else:
        offset = end_of_scope + 1
    scope = sym[start_of_scope:end_of_scope]

    if name is not None:
        return scope + b"::" + name
    elif special == 0:
        return scope + b"::" + scope
    elif special == 1:
        return scope + b"::~" + scope
    else:
        return sym


def rename_symbols(filename):
    reimpl_folder = SCRIPTS_DIR.parent / "build" / "objdiff" / "reimpl"
    orig_folder = SCRIPTS_DIR.parent / "build" / "objdiff" / "orig"

    class_name = re.sub("\\.obj$", "", filename.name)
    obj = coff.ObjectModule()
    with open(str(filename), "rb") as f:
        obj.unpack(f.read(), 0)

    # We filter to only the symbols with the namespace=filename, and we scrape everything but the function name
    seen = {}
    for sym_obj in obj.symbols:
        sym = sym_obj.get_name(obj.string_table)
        if seen.get(sym, False):
            continue
        seen[sym] = True

        demangled_sym = demangle_msvc(sym)
        if class_name.encode("utf8") not in demangled_sym.split(b"::")[0]:
            continue

        offset = obj.string_table.append(demangled_sym)
        sym_obj.name = b"\0\0\0\0" + struct.pack("I", offset)

    if not reimpl_folder.exists():
        reimpl_folder.mkdir(parents=True, exist_ok=True)
        orig_folder.mkdir(parents=True, exist_ok=True)

    with open(str(reimpl_folder / filename.name), "wb") as f:
        f.write(obj.get_buffer())


if __name__ == "__main__":
    rename_symbols(Path(sys.argv[1]))
