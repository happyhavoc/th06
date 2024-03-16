import csv
import struct
import sys


def main():
    with open(sys.argv[1]) as f:
        globals_csv = csv.reader(f)
        globals_list = [
            (glob[0].strip().encode("utf8") + b"\0", int(glob[1].strip(), 16))
            for glob in globals_csv
        ]

    coff_file = struct.pack(
        "HHIIIHH",
        0x014C,  # machine - i386
        0,  # Number of sections - we have none
        0,  # Timestamp - unnecessary
        0x14,  # Pointer to symbol table. Goes right after the COFF header
        len(globals_list),  # Number of symbols.
        0,  # Size of optional header. We don't have one.
        5,  # Characteristics. relocsStripped | lineNumsStripped
    )

    curStrTableOffset = 4
    for symbol, addr in globals_list:
        coff_file += struct.pack(
            "IIIHHBB",
            0,  # Put all names in the string table.
            curStrTableOffset,  # offset in string table
            addr,  # Address
            0xFFFF,  # SectionNumber - none of ours, we don't have one.
            0,  # Type - Null
            2,  # StorageClass - External
            0,  # NumOfAuxSymbols
        )
        curStrTableOffset += len(symbol)

    coff_file += struct.pack("I", curStrTableOffset)
    for symbol, _ in globals_list:
        coff_file += symbol

    with open(sys.argv[2], "wb") as f:
        f.write(coff_file)


if __name__ == "__main__":
    main()
