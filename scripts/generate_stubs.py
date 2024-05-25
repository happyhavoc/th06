import argparse
import csv
import sys

parser = argparse.ArgumentParser(
    prog="generate_stubs", description="Generate stubs based on the stubs.csv file."
)
parser.add_argument(
    "-o", "--output", action="store", help="File to store the generated stubs in"
)
args = parser.parse_args()

with open("config/mapping.csv") as f:
    mapping_csv = csv.reader(f)
    mapping_obj = {}
    for func in mapping_csv:
        fun_name = func[0]
        fun_addr = int(func[1], 16)
        mapping_obj[fun_name] = {
            "fun_addr": int(func[1], 16),
            "fun_size": int(func[2], 16),
            "calling_convention": func[3],
            "varargs": func[4] == "varargs",
            "ret_type": func[5],
            "arg_types": func[6:],
        }

with open("config/implemented.csv") as f:
    implemented_csv = csv.reader(f)
    for func in implemented_csv:
        mapping_obj[func[0]]["implemented"] = True


f = open("config/stubbed.csv")
stubbed_csv = csv.reader(f)

output = sys.stdout
if args.output:
    output = open(args.output, "w")

ret_vals = {
    "void": "",
    "u8": "0",
    "i8": "0",
    "u16": "0",
    "i16": "0",
    "short": "0",
    "unsigned short": "0",
    "u32": "0",
    "i32": "0",
    "unsigned int": "0",
    "int": "0",
    "unsigned long": "0",
    "long": "0",
    "f32": "0.0",
    "float": "0.0",
    "ZunResult": "ZUN_ERROR",
    "ChainCallbackResult": "CHAIN_CALLBACK_RESULT_EXIT_GAME_SUCCESS",
    "FireBulletResult": "FBR_STOP_SPAWNING",
}

for stub in stubbed_csv:
    fun_name = stub[0]
    fun = mapping_obj[fun_name]
    if fun.get("implemented", False):
        # We don't need to generate a stub for implemented functions.
        continue

    calling_convention = fun["calling_convention"]
    ret_type = fun["ret_type"]
    if ret_type.endswith("*"):
        ret_val = "NULL"
    else:
        ret_val = ret_vals[ret_type]
    args_types = fun["arg_types"]

    if calling_convention == "__thiscall":
        this_type = args_types.pop(0)

    callconv = ""
    if calling_convention == "__stdcall":
        callconv = "__stdcall"

    fun_sig = ret_type + " " + callconv + " " + fun_name + "("
    fun_sig += ", ".join(
        [arg_type + " " + "a" + str(idx) for idx, arg_type in enumerate(args_types)]
        + (["..."] if fun["varargs"] else [])
    )
    fun_sig += ")"
    print(fun_sig + " {", file=output)
    print('    printf("STUBBED: ' + fun_sig + '\\n");', file=output)
    print("    return " + ret_val + ";", file=output)
    print("}", file=output)
