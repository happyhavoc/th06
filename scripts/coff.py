"""
cough - A library for building COFF object files.

Start with the ObjectModule class:

>>> module = ObjectModule()

Now, let's create a '.text' section:

>>> section = Section(b'.text', SectionFlags.MEM_EXECUTE)

Add a bit of code:

>>> section.data = b'\x29\xc0\xc3'  # return 0
... section.size_of_raw_data = len(section.data)

Good enough, let's add it to our module:

>>> module.sections.append(section)

To make use of that bit of code, we are going to need an exported symbol:

>>> main = SymbolRecord(b'main', section_number=1, storage_class=StorageClass.EXTERNAL)

Set the value to the offset in the section:

>>> main.value = 0

And add it to our module:

>>> module.symbols.append(main)

That's enough, let's write our module to a file:

>>> with open('test.obj', 'wb') as obj_file:
...     obj_file.write(module.get_buffer())


---

Forked to turn into a single-file library and include a parser.

Original can be found @ https://github.com/d3dave/cough/
Forked by roblabla

Licensed MIT.
"""

import time
import enum
import struct

# Yes, this is kinda cheating. I don't really care though :^)


class MachineType(enum.IntEnum):
    UNKNOWN = 0x0
    AM33 = 0x1D3
    AMD64 = 0x8664
    ARM = 0x1C0
    ARM64 = 0xAA64
    ARMNT = 0x1C4
    EBC = 0xEBC
    I386 = 0x14C
    IA64 = 0x200
    M32R = 0x9041
    MIPS16 = 0x266
    MIPSFPU = 0x366
    MIPSFPU16 = 0x466
    POWERPC = 0x1F0
    POWERPCFP = 0x1F1
    R4000 = 0x166
    RISCV32 = 0x5032
    RISCV64 = 0x5064
    RISCV128 = 0x5128
    SH3 = 0x1A2
    SH3DSP = 0x1A3
    SH4 = 0x1A6
    SH5 = 0x1A8
    THUMB = 0x1C2
    WCEMIPSV2 = 0x169


class FileHeader:
    """
    Offset	Size	Field
    =====================================
       0	  2	    Machine
       2	  2	    NumberOfSections
       4	  4	    TimeDateStamp
       8	  4	    PointerToSymbolTable
      12	  4	    NumberOfSymbols
      16	  2	    SizeOfOptionalHeader
      18	  2	    Characteristics

    Machine:
        Target machine type.
    NumberOfSections:
        Indicates the size of the section table, which immediately follows the headers.
    TimeDateStamp:
        Indicates when the file was created. The low 32 bits of the number of seconds since 1970-01-01 00:00.
    PointerToSymbolTable:
        The file offset of the COFF symbol table, or zero if no COFF symbol table is present.
    NumberOfSymbols:
        The number of entries in the symbol table.
        This data can be used to locate the string table, which immediately follows the symbol table.
    SizeOfOptionalHeader:
        The size of the optional header, which is required for executable files but not for object files.
    Characteristics:
        The flags that indicate the attributes of the file.
    """

    struct = struct.Struct("<HHLLLHH")

    def __init__(self, machine=MachineType.AMD64):
        self.machine = machine
        self.number_of_sections = 0
        self.time_date_stamp = 0
        self.pointer_to_symtab = 0
        self.number_of_symbols = 0
        self.size_of_opt_header = 0
        self.characteristics = 0

    def pack(self):
        return self.struct.pack(
            self.machine,
            self.number_of_sections,
            self.time_date_stamp,
            self.pointer_to_symtab,
            self.number_of_symbols,
            self.size_of_opt_header,
            self.characteristics,
        )

    def unpack(self, buffer, offset):
        (
            self.machine,
            self.number_of_sections,
            self.time_date_stamp,
            self.pointer_to_symtab,
            self.number_of_symbols,
            self.size_of_opt_header,
            self.characteristics,
        ) = self.struct.unpack_from(buffer, offset)
        return offset + self.struct.size


class ObjectModule:
    """
    Layout:
    +-----------------+
    |     Header      |
    +-----------------+
    | Optional Header |
    +-----------------+
    | Section headers |
    +-----------------+
    |    Sections     |
    +-----------------+
    |  Symbol table   |
    +-----------------+
    |  String table   |
    +-----------------+
    """

    def __init__(self):
        self.file_header = FileHeader()
        self.optheader = b""
        self.sections = []
        self.symbols = []
        self.string_table = StringTable()

    def unpack(self, buffer, offset=0):
        offset = self.file_header.unpack(buffer, offset)
        self.optheader = buffer[offset : offset + self.file_header.size_of_opt_header]
        offset += self.file_header.size_of_opt_header
        self.sections = []
        for section in range(self.file_header.number_of_sections):
            sect = Section("tmp")
            offset = sect.unpack(buffer, offset)
            self.sections.append(sect)

        self.symbols = []
        offset = self.file_header.pointer_to_symtab
        i = 0
        while i < self.file_header.number_of_symbols:
            sym = SymbolRecord("tmp")
            offset = sym.unpack(buffer, offset)
            self.symbols.append(sym)
            # COFF format is _slightly_ insane. The `number_of_symbols` field
            # counts both the symbols themselves, but also their aux_records.
            # Meaning, a symbol containing 2 aux records counts as _three_
            # items in the number_of_symbols.
            i += 1 + len(sym.aux_records)

        # The rest is the string table.
        self.string_table.unpack(buffer, offset)

    def get_buffer(self):
        sections_buffer = self.dump_sections()
        self.file_header.time_date_stamp = int(time.time())
        self.file_header.number_of_sections = len(self.sections)
        self.file_header.number_of_symbols = len(self.symbols) + sum(
            (len(s.aux_records) for s in self.symbols)
        )

        self.file_header.pointer_to_symtab = FileHeader.struct.size + len(
            sections_buffer
        )
        body_buffer = bytearray()
        body_buffer += self.file_header.pack()
        body_buffer += sections_buffer
        for sym in self.symbols:
            body_buffer += sym.pack()
        body_buffer += self.string_table.pack()
        return bytes(body_buffer)

    def dump_sections(self):
        data_buf_offset = FileHeader.struct.size + 40 * len(self.sections)
        hdrs_buf = bytearray()
        data_buf = bytearray()
        for sec in self.sections:
            if sec.data:
                sec.pointer_to_raw_data = data_buf_offset + len(data_buf)
                data_buf += sec.data
            if sec.relocations:
                sec.pointer_to_relocations = data_buf_offset + len(data_buf)
                for reloc in sec.relocations:
                    data_buf += reloc.pack()
            if sec.line_numbers:
                sec.pointer_to_linenumbers = data_buf_offset + len(data_buf)
                for line in sec.line_numbers:
                    data_buf += line.pack()
            hdrs_buf += sec.get_header()

        return bytes(hdrs_buf + data_buf)


class LineNumber:
    """
    Offset	Size	Field
    =====================================
      0	      4	    Type(*)
      4	      2	    Linenumber


    Type:
        Union of two fields: Symbol Table Index and RVA. Whether Symbol Table Index or RVA is used depends on the
        value of Linenumber.

        SymbolTableIndex:
            Used when Linenumber is 0: index to symbol table entry for a function. This format is used to indicate the
            function that a group of line-number records refer to.
        VirtualAddress:
            Used when Linenumber is non-zero: relative virtual address of the executable code that corresponds to the
            source line indicated. In an object file, this contains the virtual address within the section.
    Linenumber:
        When nonzero, this field specifies a one-based line number. When zero, the Type field is interpreted as a
        Symbol Table Index for a function.



    """

    struct = struct.Struct("<LH")

    def __init__(self):
        self.address = 0
        self.line_number = 0

    def pack(self):
        return self.struct.pack(self.address, self.line_number)

    def unpack(self, buffer, offset):
        self.address, self.line_number = self.struct.unpack_from(buffer, offset)
        return offset + self.struct.size


class Relocation:
    """
    Offset	Size	Field
    =====================================
      0	      4	    VirtualAddress
      4	      4	    SymbolTableIndex
      8	      2	    Type

    VirtualAddress:
        The address of the item to which relocation is applied. This is the offset from the beginning of the section,
        plus the value of the section’s RVA/Offset field. For example, if the first byte of the section has an address
        of 0x10, the third byte has an address of 0x12.
    SymbolTableIndex:
        A zero-based index into the symbol table. This symbol gives the address that is to be used for the relocation.
        If the specified symbol has section storage class, then the symbol’s address is the address with the first
        section of the same name.
    Type:
        A value that indicates the kind of relocation that should be performed. Valid relocation types depend on
        machine type.
    """

    struct = struct.Struct("<LLH")

    def __init__(self):
        self.virtual_address = 0
        self.symbol_table_index = 0
        self.type = 0

    def pack(self):
        return self.struct.pack(
            self.virtual_address, self.symbol_table_index, self.type
        )

    def unpack(self, buffer, offset):
        self.virtual_address, self.symbol_table_index, self.type = (
            self.struct.unpack_from(buffer, offset)
        )
        return offset + self.struct.size


# Using intflag would be better, but that requires python 3.6+. We're stuck in
# 3.4 land for XP support.
class SectionFlags(enum.IntEnum):
    CNT_CODE = 0x00000020
    CNT_INITIALIZED_DATA = 0x00000040
    CNT_UNINITIALIZED_DATA = 0x00000080
    LNK_INFO = 0x00000200
    LNK_REMOVE = 0x00000800
    LNK_COMDAT = 0x00001000
    GPREL = 0x00008000
    ALIGN_1BYTES = 0x00100000
    ALIGN_2BYTES = 0x00200000
    ALIGN_4BYTES = 0x00300000
    ALIGN_8BYTES = 0x00400000
    ALIGN_16BYTES = 0x00500000
    ALIGN_32BYTES = 0x00600000
    ALIGN_64BYTES = 0x00700000
    ALIGN_128BYTES = 0x00800000
    ALIGN_256BYTES = 0x00900000
    ALIGN_512BYTES = 0x00A00000
    ALIGN_1024BYTES = 0x00B00000
    ALIGN_2048BYTES = 0x00C00000
    ALIGN_4096BYTES = 0x00D00000
    ALIGN_8192BYTES = 0x00E00000
    LNK_NRELOC_OVFL = 0x01000000
    MEM_DISCARDABLE = 0x02000000
    MEM_NOT_CACHED = 0x04000000
    MEM_NOT_PAGED = 0x08000000
    MEM_SHARED = 0x10000000
    MEM_EXECUTE = 0x20000000
    MEM_READ = 0x40000000
    MEM_WRITE = 0x80000000


class Section:
    """
    Header struct:

    Offset	Size	Field
    =====================================
       0	  8	    Name
       8	  4	    VirtualSize
      12	  4	    VirtualAddress
      16	  4	    SizeOfRawData
      20	  4	    PointerToRawData
      24	  4	    PointerToRelocations
      28	  4	    PointerToLinenumbers
      32	  2	    NumberOfRelocations
      34	  2	    NumberOfLinenumbers
      36	  4	    Characteristics

    Name:
        An 8-byte, null-padded UTF-8 encoded string. If the string is exactly 8 characters long, there is no
        terminating null. For longer names, this field contains a slash (/) that is followed by an ASCII
        representation of a decimal number that is an offset into the string table. Long names in object files are
        truncated if they are emitted to an executable file.
    VirtualSize:
        The total size of the section when loaded into memory. Should be set to zero.
    VirtualAddress:
        The address of the first byte of the section relative to the image base when the section is loaded into memory.
        This field is the address of the first byte before relocation is applied; for simplicity, compilers should set
        this to zero. Otherwise, it is an arbitrary value that is subtracted from offsets during relocation.
    SizeOfRawData:
        The size of the section. If this is less than VirtualSize, the remainder of the section is zero-filled. Because
        the SizeOfRawData field is rounded but the VirtualSize field is not, it is possible for SizeOfRawData to be
        greater than VirtualSize as well. When a section contains only uninitialized data, this field should be zero.
    PointerToRawData:
        The file pointer to the first page of the section within the COFF file. The value should be aligned on a 4-byte
        boundary for best performance. When a section contains only uninitialized data, this field should be zero.
    PointerToRelocations:
        The file pointer to the beginning of relocation entries for the section. This is set to zero if there are no
        relocations.
    PointerToLinenumbers:
        The file pointer to the beginning of line-number entries for the section. This is set to zero if there are no
        COFF line numbers.
    NumberOfRelocations:
        The number of relocation entries for the section.
    NumberOfLinenumbers:
        The number of line-number entries for the section.
    Characteristics:
        The flags that describe the characteristics of the section.
    """

    header_struct = struct.Struct("<8sLLLLLLHHL")

    def __init__(self, name, flags=None, data=None):
        self.name = name
        self.flags = flags or 0
        self.data = data
        self.relocations = []
        self.line_numbers = []
        self.virtual_size = 0
        self.virtual_address = 0
        self.size_of_raw_data = len(data) if data else 0
        self.pointer_to_raw_data = 0
        self.pointer_to_relocations = 0
        self.pointer_to_linenumbers = 0
        self.number_of_relocations = 0
        self.number_of_linenumbers = 0

    def get_header(self):
        return self.header_struct.pack(
            self.name,
            self.virtual_size,
            self.virtual_address,
            self.size_of_raw_data,
            self.pointer_to_raw_data,
            self.pointer_to_relocations,
            self.pointer_to_linenumbers,
            self.number_of_relocations,
            self.number_of_linenumbers,
            self.flags,
        )

    def unpack(self, buffer, offset):
        (
            self.name,
            self.virtual_size,
            self.virtual_address,
            self.size_of_raw_data,
            self.pointer_to_raw_data,
            self.pointer_to_relocations,
            self.pointer_to_linenumbers,
            self.number_of_relocations,
            self.number_of_linenumbers,
            self.flags,
        ) = self.header_struct.unpack_from(buffer, offset)

        if (
            not self.flags & SectionFlags.CNT_UNINITIALIZED_DATA
            and self.pointer_to_raw_data != 0
        ):
            self.data = buffer[
                self.pointer_to_raw_data : self.pointer_to_raw_data
                + self.size_of_raw_data
            ]

        self.relocations = []
        self.line_numbers = []
        reloc_offset = self.pointer_to_relocations
        line_offset = self.pointer_to_linenumbers
        for i in range(self.number_of_relocations):
            reloc = Relocation()
            reloc_offset = reloc.unpack(buffer, reloc_offset)
            self.relocations.append(reloc)

        for i in range(self.number_of_linenumbers):
            line = LineNumber()
            line_offset = line.unpack(buffer, line_offset)
            self.line_numbers.append(line)

        return offset + self.header_struct.size


class StringTable:
    """
    Layout:
    +-----------------+
    |  Size of table  |
    +-----------------+
    |     Strings     |
    +-----------------+
    Size is in bytes and contains the 4 bytes required to write it.
    """

    def __init__(self):
        self._size = 4
        self._strings = []

    @staticmethod
    def _check(value):
        if not isinstance(value, bytes):
            raise ValueError("value must be an encoded string")

    def __len__(self):
        return len(self._strings)

    def __getitem__(self, item):
        return self._strings[item]

    def __setitem__(self, key, value):
        self._check(value)
        self._strings[key] = value

    def __contains__(self, item):
        return item in self._strings

    def __iter__(self):
        return iter(self._strings)

    def append(self, item):
        """
        Adds a new item to the string table, and returns its offset. This offset
        may be used when referencing this string in the symbol name field.
        """
        self._check(item)
        self._strings.append(item)
        cur_offset = self._size
        self._size += len(item) + 1
        return cur_offset

    def get_string_at_offset(self, offset):
        offset -= 4
        for s in self:
            if 0 <= offset < len(s):
                return s[offset:]
            offset -= len(s) + 1
        return None

    def pack(self):
        buffer = bytearray()
        buffer += self._size.to_bytes(4, "little", signed=False)
        for s in self._strings:
            buffer += s + b"\0"
        return bytes(buffer)

    def unpack(self, buffer, offset):
        (size,) = struct.unpack("I", buffer[offset : offset + 4])
        self._strings = buffer[offset + 4 : offset + size].split(b"\0")
        if buffer[offset + size - 1] == 0 and len(self._strings[-1]) == 0:
            # Remove extra empty string at the end.
            self._strings.pop()
        self._size = size


class SpecialSectionNumber(enum.IntEnum):
    UNDEFINED = 0
    ABSOLUTE = -1
    DEBUG = -2


class StorageClass(enum.IntEnum):
    END_OF_FUNCTION = -1
    NULL = 0
    AUTOMATIC = 1
    EXTERNAL = 2
    STATIC = 3
    REGISTER = 4
    EXTERNAL_DEF = 5
    LABEL = 6
    UNDEFINED_LABEL = 7
    MEMBER_OF_STRUCT = 8
    ARGUMENT = 9
    STRUCT_TAG = 10
    MEMBER_OF_UNION = 11
    UNION_TAG = 12
    TYPE_DEFINITION = 13
    UNDEFINED_STATIC = 14
    ENUM_TAG = 15
    MEMBER_OF_ENUM = 16
    REGISTER_PARAM = 17
    BIT_FIELD = 18
    BLOCK = 100
    FUNCTION = 101
    END_OF_STRUCT = 102
    FILE = 103
    SECTION = 104.0
    WEAK_EXTERNAL = 105
    CLR_TOKEN = 107


class BaseType(enum.IntEnum):
    NULL = 0
    VOID = 1
    CHAR = 2
    SHORT = 3
    INT = 4
    LONG = 5
    FLOAT = 6
    DOUBLE = 7
    STRUCT = 8
    UNION = 9
    ENUM = 10
    MOE = 11
    BYTE = 12
    WORD = 13
    UINT = 14
    DWORD = 15


class ComplexType(enum.IntEnum):
    NULL = 0
    POINTER = 1
    FUNCTION = 2
    ARRAY = 3


def mktype(base, comp):
    return (comp << 8) + base


class SymbolRecord:
    record_struct = struct.Struct("<8sLhHBB")

    def __init__(
        self,
        name,
        typ=None,
        section_number=SpecialSectionNumber.UNDEFINED,
        storage_class=StorageClass.NULL,
    ):
        self.name = name
        self.value = None
        self.section_number = section_number
        self.type = typ or 0
        self.storage_class = storage_class
        self.aux_records = []

    def pack(self):
        packed_aux_records = b"".join(self.aux_records)
        if len(packed_aux_records) % 18 != 0:
            raise ValueError("auxiliary records length must be a multiple of 18")
        return (
            self.record_struct.pack(
                self.name,
                self.value,
                self.section_number,
                self.type,
                self.storage_class,
                len(self.aux_records),
            )
            + packed_aux_records
        )

    def unpack(self, buffer, offset):
        (
            self.name,
            self.value,
            self.section_number,
            self.type,
            self.storage_class,
            aux_records_len,
        ) = self.record_struct.unpack_from(buffer, offset)
        offset += self.record_struct.size
        self.aux_records = [
            buffer[offset + i * 18 : offset + (i + 1) * 18]
            for i in range(aux_records_len)
        ]
        return offset + aux_records_len * 18

    def get_name(self, string_table):
        if self.name[0:4] == b"\0\0\0\0":
            (offset,) = struct.unpack("I", self.name[4:8])
            return string_table.get_string_at_offset(offset)
        else:
            return self.name.split(b"\0")[0]
