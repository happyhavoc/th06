import base64
import os.path
from pathlib import Path
import sys

script_path = Path(os.path.dirname(os.path.realpath(__file__))) / ".."


def get_file(fp):
    try:
        with open(fp, "r") as file:
            return file.readlines()

    except FileNotFoundError:
        print("couldn't open " + str(fp) + " file")
        print("hint: try running the ci from the project root")
        exit(1)


def create_status_profile():
    impl = get_file(script_path / "config" / "implemented.csv")
    maps = get_file(script_path / "config" / "mapping.csv")

    total_func_bytes = 246112  # number of function bytes
    impl_bytes = 0
    num_funcs = 0

    for f_name, location, size, *rest in (line.split(",") for line in maps):
        if (
            int(location.removeprefix("0x"), 16) > 4444512
        ):  # 0x0043d160 is where 3rd party lib functions start
            break

        num_funcs += 1

        if f_name + "\n" in impl:
            impl_bytes += int(size.removeprefix("0x"), 16)


    raw_func_percentage = len(impl) / num_funcs * 100
    byte_impl_percentage = impl_bytes / total_func_bytes * 100

    return raw_func_percentage, byte_impl_percentage


def update_svg():
    with open(script_path / "resources" / "progress_template.svg", "r") as f:
        svg_data = f.read()

    func_impl, bytes_impl = create_status_profile()

    with open(script_path / "resources" / "placeholder.png", "rb") as f:
        placeholder_png = f.read()
    icon_url = "data:image/png;base64," + base64.b64encode(placeholder_png).decode(
        "ascii"
    )

    new_svg = (
        svg_data.replace("{FUNC_PROG_PERCENT}", str(round(func_impl, 2)))
        .replace("{BYTES_PROG_PERCENT}", str(round(bytes_impl, 2)))
        .replace("{ICON_URL}", icon_url)
    )

    with open(script_path / "resources" / "progress_dark.svg", "w") as f:
        f.write(new_svg.replace("{TEXT_COLOR}", "white"))

    with open(script_path / "resources" / "progress.svg", "w") as f:
        f.write(new_svg.replace("{TEXT_COLOR}", "black"))

def get_unimplemented():
    impl = get_file(script_path / "config" / "implemented.csv")
    maps = get_file(script_path / "config" / "mapping.csv")

    unimplemented = []
    for f_name, location, *unused in (line.split(",") for line in maps):
        if (
            int(location.removeprefix("0x"), 16) > 4444512
        ):  # 0x0043d160 is where 3rd party lib functions start
            break

        if f_name + "\n" not in impl:
            unimplemented.append(f_name)

    for f in unimplemented:
        print(f)
    
    return unimplemented
    

def main():
    if "gen_svg" in sys.argv:
        update_svg()
        print("SVG file updated!\n")
    if "get_unimplemented" in sys.argv:
        unimplemented = get_unimplemented()
        print("\n" + str(len(unimplemented)), "Unimplemented functions!")


    raw_func_percentage, byte_impl_percentage = create_status_profile()

    print(round(raw_func_percentage, 2), "% func implemented")
    print(round(byte_impl_percentage, 2), "% size implemented")


if __name__ == "__main__":
    main()
