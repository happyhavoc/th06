import argparse
import csv
import sys

parser = argparse.ArgumentParser(
    prog="generate_detours", description="Generate stubs based on the stubs.csv file."
)
parser.add_argument(
    "-o", "--output", action="store", help="File to store the generated stubs in"
)
parser.add_argument(
    "-i", "--input-def", action="store", help="Def file to find mangled symbols in"
)
args = parser.parse_args()


def get_path_of_mangled_symbol(symbol):
    if symbol[0] == "?":
        cpp_symbol = symbol[1:]
        path = cpp_symbol.split("@")
        last = next((idx for idx, x in enumerate(path) if x == ""), None)
        path = path[0:last]

        first_elem = path[0]
        if first_elem[0] == "?":
            if first_elem[1] == "0":
                cls = first_elem[2:]
                path[0] = cls + "::" + cls
            elif first_elem[1] == "1":
                cls = first_elem[2:]
                path[0] = cls + "::~" + cls
            elif first_elem[1:3] == "_H":
                return None
            else:
                print("WARNING: Unknown special symbol " + symbol)

        return "::".join(reversed(path))
    elif symbol[0] == "_":
        return symbol[1:].split("@", 1)[0]
    else:
        raise Exception("Unknown symbol kind " + symbol)


fun_to_mangled_map = {}
with open(args.input_def) as f:
    for line in f:
        if len(line.strip()) == 0:
            continue

        if line.strip() == "EXPORTS":
            continue

        mangled_symbol = line.rsplit(" ", 1)[0].strip()
        fun_path = get_path_of_mangled_symbol(mangled_symbol)
        if fun_path is None:
            continue
        print(fun_path)
        if fun_path in fun_to_mangled_map:
            raise Exception("Overload detected, two functions patch " + fun_path)
        fun_to_mangled_map[fun_path] = mangled_symbol

fun_to_mangled_map["operator_new"] = "??2@YAPAXI@Z"
fun_to_mangled_map["_malloc"] = "malloc"
fun_to_mangled_map["_calloc"] = "calloc"
fun_to_mangled_map["_realloc"] = "realloc"
fun_to_mangled_map["_free"] = "free"
fun_to_mangled_map["__msize"] = "_msize"

with open("config/mapping.csv") as f:
    mapping_csv = csv.reader(f)
    mapping_obj = {}
    for func in mapping_csv:
        fun_name = func[0]
        fun_addr = int(func[1], 16)
        mapping_obj[fun_name] = fun_addr

detours = {}
f = open("config/implemented.csv")
implemented_csv = csv.reader(f)

for implemented in implemented_csv:
    fun_name = implemented[0]
    fun_mangled_name = fun_to_mangled_map[fun_name]
    fun_addr = mapping_obj[fun_name]
    detours[fun_name] = {
        "fun_addr": fun_addr,
        "fun_mangled_name": fun_mangled_name,
        "stub": False,
    }

f = open("config/stubbed.csv")
stubbed_csv = csv.reader(f)
for implemented in stubbed_csv:
    fun_name = implemented[0]
    fun_mangled_name = fun_to_mangled_map[fun_name]
    fun_addr = mapping_obj[fun_name]
    detours[fun_name] = {
        "fun_addr": fun_addr,
        "fun_mangled_name": fun_mangled_name,
        "stub": True,
    }

# Add some necessary detouring to share MSVCRT heap with the main executable
for fun_name in ["_malloc", "_calloc", "_realloc", "operator_new", "_free", "__msize"]:
    fun_mangled_name = fun_to_mangled_map[fun_name]
    fun_addr = mapping_obj[fun_name]
    detours[fun_name] = {
        "fun_addr": fun_addr,
        "fun_mangled_name": fun_mangled_name,
        "stub": False,
    }

output = sys.stdout
if args.output:
    output = open(args.output, "w")

print("Detouring detours[] = {", file=output)

first = True
for detour in detours.values():
    if not first:
        print(",", file=output)
    first = False
    print(
        "    { "
        + hex(detour["fun_addr"])
        + ', "'
        + detour["fun_mangled_name"]
        + '", '
        + str(detour["stub"]).upper()
        + " }",
        end="",
        file=output,
    )

print("\n};", file=output)
