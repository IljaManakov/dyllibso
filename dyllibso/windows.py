from __future__ import annotations
import contextlib
from datetime import datetime
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from functools import cached_property
from io import FileIO
from pathlib import Path
from typing import Callable, Any, NamedTuple

COFF_HEADER_POINTER_OFFSET = 0x3c
COFF_HEADER_POINTER_SIZE = 4
COFF_HEADER_BYTE_SIZE = 20


def _little_endian(byte_input: bytes) -> int:
    return int.from_bytes(byte_input, "little")

def _extract_ascii_string(pefile, *, rva=0, offset=0):
    pefile.seek(rva=rva, offset=offset)
    string = bytes()
    while (next_char := pefile.read(1)) != b"\x00":
        string += next_char
    return string.decode("ascii")



class _BytesDecoder:

    def __init__(self, byte_input: bytes, decode: Callable[[bytes], Any] | None = _little_endian):
        self.bytes = byte_input
        self.offset = 0
        self.decode = decode

    def next(self, n: int, skip_before: int = 0, skip_after: int = 0) -> Any:
        self.offset += skip_before
        if self.offset + n > len(self.bytes):
            raise StopIteration(self.bytes[self.offset:])
        start = self.offset
        stop = self.offset + n
        value = self.bytes[start:stop]
        self.offset = stop + skip_after
        if self.decode is not None:
            value = self.decode(value)
        return value

    def rest(self) -> bytes:
        return self.bytes[self.offset:]


class MachineType(IntEnum):
    UNKNOWN = 0x0           #: The content of this field is assumed to be applicable to any machine type
    ALPHA = 0x184           #: Alpha AXP, 32 - bit address space
    ALPHA64 = 0x284         #: Alpha 64, 64 - bit address space
    AM33 = 0x1d3            #: Matsushita AM33
    AMD64 = 0x8664          #: x64
    ARM = 0x1c0             #: ARM little endian
    ARM64 = 0xaa64          #: ARM64 little endian
    ARM64EC = 0xA641        #: ABI that enables interoperability between native ARM64 and emulated x64 code.
    ARM64X = 0xA64E         #: Binary format that allows both native ARM64 and ARM64EC code to coexist in the same file.
    ARMNT = 0x1c4           #: ARM Thumb - 2 little endian
    AXP64 = 0x284           #: AXP 64(Same as Alpha 64)
    EBC = 0xebc             #: EFI byte code
    I386 = 0x14c            #: Intel 386 or later processors and compatible processors
    IA64 = 0x200            #: Intel Itanium processor family
    LOONGARCH32 = 0x6232    #: LoongArch 32 - bit processor family
    LOONGARCH64 = 0x6264    #: LoongArch 64 - bit processor family
    M32R = 0x9041           #: Mitsubishi M32R little endian
    MIPS16 = 0x266          #: MIPS16
    MIPSFPU = 0x366         #: MIPS with FPU
    MIPSFPU16 = 0x466       #: MIPS16 with FPU
    POWERPC = 0x1f0         #: Power PC little endian
    POWERPCFP = 0x1f1       #: Power PC with floating point support
    R3000BE = 0x160         #: MIPS I compatible 32 - bit big endian
    R3000 = 0x162           #: MIPS I compatible 32 - bit little endian
    R4000 = 0x166           #: MIPS III compatible 64 - bit little endian
    R10000 = 0x168          #: MIPS IV compatible 64 - bit little endian
    RISCV32 = 0x5032        #: RISC - V 32 - bit address space
    RISCV64 = 0x5064        #: RISC - V 64 - bit address space
    RISCV128 = 0x5128       #: RISC - V 128 - bit address space
    SH3 = 0x1a2             #: Hitachi SH3
    SH3DSP = 0x1a3          #: Hitachi SH3 DSP
    SH4 = 0x1a6             #: Hitachi SH4
    SH5 = 0x1a8             #: Hitachi SH5
    THUMB = 0x1c2           #: Thumb
    WCEMIPSV2 = 0x169       #: MIPS little - endian WCE v2


class Characteristics(IntFlag):
    RELOCS_STRIPPED = 0x0001            #: Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files.
    EXECUTABLE_IMAGE = 0x0002           #: Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
    LINE_NUMS_STRIPPED = 0x0004         #: COFF line numbers have been removed. This flag is deprecated and should be zero.
    LOCAL_SYMS_STRIPPED = 0x0008        #: COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
    AGGRESSIVE_WS_TRIM = 0x0010         #: Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
    LARGE_ADDRESS_AWARE = 0x0020        #: Application can handle > 2-GB addresses. = 0x0040   # This flag is reserved for future use.
    BYTES_REVERSED_LO = 0x0080          #: Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
    ARCH_32BIT_MACHINE = 0x0100         #: Machine is based on a 32-bit-word architecture.
    DEBUG_STRIPPED = 0x0200             #: Debugging information is removed from the image file.
    REMOVABLE_RUN_FROM_SWAP = 0x0400    #: If the image is on removable media, fully load it and copy it to the swap file.
    NET_RUN_FROM_SWAP = 0x0800          #: If the image is on network media, fully load it and copy it to the swap file.
    SYSTEM = 0x1000                     #: The image file is a system file, not a user program.
    DLL = 0x2000                        #: The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
    UP_SYSTEM_ONLY = 0x4000             #: The file should be run only on a uniprocessor machine.
    BYTES_REVERSED_HI = 0x8000          #: Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.


class Subsystem(IntEnum):
    UNKNOWN = 0                     #: An unknown subsystem
    NATIVE = 1                      #: Device drivers and native Windows processes
    WINDOWS_GUI = 2                 #: The Windows graphical user interface (GUI) subsystem
    WINDOWS_CUI = 3                 #: The Windows character subsystem
    OS2_CUI = 5                     #: The OS/2 character subsystem
    POSIX_CUI = 7                   #: The Posix character subsystem
    NATIVE_WINDOWS = 8              #: Native Win9x driver
    WINDOWS_CE_GUI = 9              #: Windows CE
    EFI_APPLICATION = 10            #: An Extensible Firmware Interface (EFI) application
    EFI_BOOT_SERVICE_DRIVER = 11    #: An EFI driver with boot services
    EFI_RUNTIME_DRIVER = 12         #: An EFI driver with run-time services
    EFI_ROM = 13                    #: An EFI ROM image
    XBOX = 14                       #: XBOX
    WINDOWS_BOOT_APPLICATION = 16   #: Windows boot application.


class DLLCharacteristics(IntFlag):
    HIGH_ENTROPY_VA = 0x0020        #: Image can handle a high entropy 64-bit virtual address space.
    DYNAMIC_BASE = 0x0040           #: DLL can be relocated at load time.
    FORCE_INTEGRITY = 0x0080        #: Code Integrity checks are enforced.
    NX_COMPAT = 0x0100              #: Image is NX compatible.
    NO_ISOLATION = 0x0200           #: Isolation aware, but do not isolate the image.
    NO_SEH = 0x0400                 #: Does not use structured exception (SE) handling. No SE handler may be called in this image.
    NO_BIND = 0x0800                #: Do not bind the image.
    APPCONTAINER = 0x1000           #: Image must execute in an AppContainer.
    WDM_DRIVER = 0x2000             #: A WDM driver.
    GUARD_CF = 0x4000               #: Image supports Control Flow Guard.
    TERMINAL_SERVER_AWARE = 0x8000  #: Terminal Server aware.
    
    
class SectionCharacteristics(IntFlag):
    IMAGE_SCN_TYPE_NO_PAD = 0x00000008              #: The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files. = 0x00000010   #: Reserved for future use.
    IMAGE_SCN_CNT_CODE = 0x00000020                 #: The section contains executable code.
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040     #: The section contains initialized data.
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080   #: The section contains uninitialized data.
    IMAGE_SCN_LNK_INFO = 0x00000200                 #: The section contains comments or other information. The .drectve section has this type. This is valid for object files only. = 0x00000400   #: Reserved for future use.
    IMAGE_SCN_LNK_REMOVE = 0x00000800               #: The section will not become part of the image. This is valid only for object files.
    IMAGE_SCN_LNK_COMDAT = 0x00001000               #: The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
    IMAGE_SCN_GPREL = 0x00008000                    #: The section contains data referenced through the global pointer (GP).
    IMAGE_SCN_ALIGN_1BYTES = 0x00100000             #: Align data on a 1-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_2BYTES = 0x00200000             #: Align data on a 2-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_4BYTES = 0x00300000             #: Align data on a 4-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_8BYTES = 0x00400000             #: Align data on an 8-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_16BYTES = 0x00500000            #: Align data on a 16-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_32BYTES = 0x00600000            #: Align data on a 32-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_64BYTES = 0x00700000            #: Align data on a 64-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_128BYTES = 0x00800000           #: Align data on a 128-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_256BYTES = 0x00900000           #: Align data on a 256-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_512BYTES = 0x00A00000           #: Align data on a 512-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000          #: Align data on a 1024-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000          #: Align data on a 2048-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000          #: Align data on a 4096-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000          #: Align data on an 8192-byte boundary. Valid only for object files.
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000          #: The section contains extended relocations.
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000          #: The section can be discarded as needed.
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000           #: The section cannot be cached.
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000            #: The section is not pageable.
    IMAGE_SCN_MEM_SHARED = 0x10000000               #: The section can be shared in memory.
    IMAGE_SCN_MEM_EXECUTE = 0x20000000              #: The section can be executed as code.
    IMAGE_SCN_MEM_READ = 0x40000000                 #: The section can be read.
    IMAGE_SCN_MEM_WRITE = 0x80000000                #: The section can be written to.


@dataclass
class COFFHeader:
    machine: MachineType
    number_of_sections: int
    time_date_stamp: datetime
    pointer_to_symbol_table: int
    number_of_symbols: int
    size_of_optional_header: int
    characteristics: int

    @classmethod
    def from_bytes(cls, byte_input: bytes):
        if not len(byte_input) == COFF_HEADER_BYTE_SIZE:
            raise ValueError(f"PE file headers should be 20 bytes long. Got {len(byte_input)} instead.")
        decoder = _BytesDecoder(byte_input)
        return cls(
            machine = MachineType(decoder.next(2)),
            number_of_sections = decoder.next(2),
            time_date_stamp = datetime.fromtimestamp(decoder.next(4)),
            pointer_to_symbol_table = decoder.next(4),
            number_of_symbols = decoder.next(4),
            size_of_optional_header = decoder.next(2),
            characteristics = Characteristics(decoder.next(2)),
        )


class DataDirectoryHeader(NamedTuple):
    name: str
    address: int
    size: int


@dataclass
class DataDirectories:
    exports: DataDirectoryHeader | None = None
    imports: DataDirectoryHeader | None = None
    resources: DataDirectoryHeader | None = None
    exceptions: DataDirectoryHeader | None = None
    certificates: DataDirectoryHeader | None = None  # This one is special, because the address is a file offset instead of an RVA. (Certificates aren't loaded into memory)
    relocations: DataDirectoryHeader | None = None
    debug: DataDirectoryHeader | None = None
    _architecture: DataDirectoryHeader | None = None  # This one apparently is reserved and must always be zero. We include it for easier parsing
    global_pointer: DataDirectoryHeader | None = None
    thread_local_storage: DataDirectoryHeader | None = None
    load_configs: DataDirectoryHeader | None = None
    bound_imports: DataDirectoryHeader | None = None
    import_addresses: DataDirectoryHeader | None = None
    delay_imports: DataDirectoryHeader | None = None
    clr_runtime: DataDirectoryHeader | None = None

    def __post_init__(self):
        if self.global_pointer:
            assert self.global_pointer.size == 0  # Sanity check. According to the spec this has to always be 0.
        assert self._architecture is None
        del self._architecture

    @classmethod
    def from_bytes(cls, byte_input: bytes, num_entries: int):
        decoder = _BytesDecoder(byte_input)
        field_names = cls.__dataclass_fields__
        all_tables = {}
        for name, _ in zip(field_names, range(num_entries)):
            address = decoder.next(4)
            size = decoder.next(4)
            all_tables[name] = DataDirectoryHeader(name, address, size) if address else None
        return cls(**all_tables)



@dataclass
class OptionalHeader:
    magic: int
    major_linker_version: int
    minor_linker_version: int
    size_of_code: int
    size_of_initialized_data: int
    size_of_uninitialized_data: int
    address_of_entry_point: int
    base_of_code: int
    base_of_data: int | None
    image_base: int
    section_alignment: int
    file_alignment: int
    major_operating_system_version: int
    minor_operating_system_version: int
    major_image_version: int
    minor_image_version: int
    major_subsystem_version: int
    minor_subsystem_version: int
    size_of_image: int
    size_of_headers: int
    check_sum: int
    subsystem: Subsystem
    dll_characteristics: DLLCharacteristics
    size_of_stack_reserve: int
    size_of_stack_commit: int
    size_of_heap_reserve: int
    size_of_heap_commit: int
    number_of_rva_and_sizes: int
    data_directories: DataDirectories

    @cached_property
    def is64bit(self) -> bool:
        return self.magic == 0x20b

    @classmethod
    def from_bytes(cls, byte_input: bytes):
        decoder = _BytesDecoder(byte_input)
        magic = decoder.next(2)
        is64 = magic == 0x20b

        return cls(
            magic = magic,
            major_linker_version = decoder.next(1),
            minor_linker_version = decoder.next(1),
            size_of_code = decoder.next(4),
            size_of_initialized_data = decoder.next(4),
            size_of_uninitialized_data = decoder.next(4),
            address_of_entry_point = decoder.next(4),
            base_of_code = decoder.next(4),
            base_of_data = None if is64 else decoder.next(4),
            image_base = decoder.next(8 if is64 else 4),
            section_alignment = decoder.next(4),
            file_alignment = decoder.next(4),
            major_operating_system_version = decoder.next(2),
            minor_operating_system_version = decoder.next(2),
            major_image_version = decoder.next(2),
            minor_image_version = decoder.next(2),
            major_subsystem_version = decoder.next(2),
            minor_subsystem_version = decoder.next(2, skip_after=4),
            size_of_image = decoder.next(4),
            size_of_headers = decoder.next(4),
            check_sum = decoder.next(4),
            subsystem = Subsystem(decoder.next(2)),
            dll_characteristics = DLLCharacteristics(decoder.next(2)),
            size_of_stack_reserve = decoder.next(8 if is64 else 4),
            size_of_stack_commit = decoder.next(8 if is64 else 4),
            size_of_heap_reserve = decoder.next(8 if is64 else 4),
            size_of_heap_commit = decoder.next(8 if is64 else 4, skip_after=4),
            number_of_rva_and_sizes = (n_data_directories := decoder.next(4)),
            data_directories=DataDirectories.from_bytes(decoder.rest(), n_data_directories)
        )


@dataclass
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    pointer_to_relocations: int
    pointer_to_linenumbers: int
    number_of_relocations: int
    number_of_linenumbers: int
    characteristics: SectionCharacteristics

    @classmethod
    def from_bytes(cls, byte_input: bytes):
        name = byte_input[:8].decode().replace(b"\x00".decode(), "")
        decoder = _BytesDecoder(byte_input[8:])
        return cls(
            name = name,
            virtual_size = decoder.next(4),
            virtual_address = decoder.next(4),
            size_of_raw_data = decoder.next(4),
            pointer_to_raw_data = decoder.next(4),
            pointer_to_relocations = decoder.next(4),
            pointer_to_linenumbers = decoder.next(4),
            number_of_relocations = decoder.next(2),
            number_of_linenumbers = decoder.next(2),
            characteristics= SectionCharacteristics(decoder.next(4)),
        )


@dataclass
class ImportLookupTableEntry:
    parent: IData
    import_by_ordinal: bool
    ordinal: int | None
    hint_name_table_rva: int | None
    _hint_name: tuple[int, str] = field(default=None, repr=False, init=False)

    @classmethod
    def from_bytes(cls, parent: IData, byte_input: bytes):
        assert len(byte_input) in (4, 8)
        import_by_ordinal = bool(byte_input[-2])
        if import_by_ordinal:
            ordinal = _little_endian(byte_input[0:2])
            rva = None
        else:
            ordinal = None
            rva = _little_endian(byte_input[0:4])

        return cls(
            parent=parent,
            import_by_ordinal=import_by_ordinal,
            ordinal=ordinal,
            hint_name_table_rva = rva,
        )

    def _read_hint_name(self) -> tuple[int, str]:
        with self.parent.pefile.open_file_handle():
            self.parent.pefile.seek(rva=self.hint_name_table_rva)
            hint = _little_endian(self.parent.pefile.read(2))
            name = _extract_ascii_string(self.parent.pefile, rva=self.hint_name_table_rva + 2)
        self._hint_name = hint, name
        return self._hint_name

    @cached_property
    def hint(self) -> int:
        return self._hint_name[0] if self._hint_name else self._read_hint_name()[0]

    @cached_property
    def symbol(self) -> str:
        return self._hint_name[1] if self._hint_name else self._read_hint_name()[1]


@dataclass
class ImportDirectoryEntry:
    parent: IData
    lookup_table_rva: int
    datetime_stamp: datetime
    forwarder_chain: int
    name_rva: int
    address_table_rva: int

    @classmethod
    def from_bytes(cls, parent: IData, bytes_input: bytes):
        decoder = _BytesDecoder(bytes_input)
        return cls(
            parent=parent,
            lookup_table_rva=decoder.next(4),
            datetime_stamp=datetime.fromtimestamp(decoder.next(4)),
            forwarder_chain=decoder.next(4),
            name_rva=decoder.next(4),
            address_table_rva=decoder.next(4)
        )

    @cached_property
    def name(self):
        with self.parent.pefile.open_file_handle():
            name = _extract_ascii_string(self.parent.pefile, rva=self.name_rva)
        return name


@dataclass
class IData:
    pefile: PEFile
    directory_table: list[ImportDirectoryEntry]
    import_lookup_table: list[list[ImportLookupTableEntry]]

    @classmethod
    def from_pefile(cls, pefile: PEFile):
        instance = cls(pefile, [], [])
        with pefile.open_file_handle():
            pefile.seek(rva=pefile.optional_header.data_directories.imports.address)
            while (entry := ImportDirectoryEntry.from_bytes(instance, pefile.read(20))).name_rva:
                instance.directory_table.append(entry)

            entry_size = 8 if pefile.optional_header.is64bit else 4
            for directory in instance.directory_table:
                inner_lookup = []
                pefile.seek(rva=directory.lookup_table_rva)
                while int.from_bytes(lookup_entry := pefile.read(entry_size), "little"):
                    inner_lookup.append(ImportLookupTableEntry.from_bytes(instance, lookup_entry))
                instance.import_lookup_table.append(inner_lookup)

        return instance


class PEFile:

    def __init__(self, lib: Path):
        self.file = lib
        with self.open_file_handle() as handle:
            handle.seek(COFF_HEADER_POINTER_OFFSET)
            header_offset = _little_endian(handle.read(COFF_HEADER_POINTER_SIZE))
            handle.seek(header_offset)
            signature = handle.read(4)
            if not signature == b"PE\x00\x00":
                handle.close()
                raise ValueError("Did not find the correct signature at the start of the header.\n"
                                 "The provided binary is not a valid Windows PE file.")
            self.coff_header = COFFHeader.from_bytes(handle.read(COFF_HEADER_BYTE_SIZE))
            self.optional_header = OptionalHeader.from_bytes(handle.read(self.coff_header.size_of_optional_header))
            self.sections = {(section := Section.from_bytes(handle.read(40))).name: section for _ in range(self.coff_header.number_of_sections)}

    @cached_property
    def idata(self):
        return IData.from_pefile(self)

    def rva_to_file_offset(self, rva: int) -> int:
        try:
            containing_section = next(section for section in self.sections.values() if section.virtual_address + section.virtual_size > rva)
        except StopIteration:
            raise ValueError("Could not find a containing section for the given RVA. It appear to point outside of the memory blick of this DLL.")
        delta = rva - containing_section.virtual_address
        return containing_section.pointer_to_raw_data + delta

    @contextlib.contextmanager
    def open_file_handle(self):
        try:
            if not hasattr(self, "_handle") or not self._handle:
                self._handle = [open(self.file, "rb")]
            else:
                self._handle.append(None)
            yield self._handle[0]
        finally:
            if len(self._handle) == 1:
                self._handle[0].close()
                self._handle = None
            else:
                self._handle.pop()


    def seek(self, *, rva: int = 0, offset: int = 0) -> None:
        if not rva ^ offset:
            raise ValueError("Either rva or offset must be specified")
        if self._handle is None:
            raise ValueError("No open handle to the PE file on disk.\n"
                             "Please make sure to only use this method within a 'open_file_handle' context.")
        if rva:
            offset = self.rva_to_file_offset(rva)
        self._handle[0].seek(offset)

    def read(self, size: int) -> bytes:
        if self._handle is None:
            raise ValueError("No open handle to the PE file on disk.\n"
                             "Please make sure to only use this method within a 'open_file_handle' context.")
        return self._handle[0].read(size)


def get_dependencies(lib: Path) -> list[str]:
    file = PEFile(lib)
    with file.open_file_handle():
        deps =  [_extract_ascii_string(file, rva=entry.name_rva)  for entry in file.idata.directory_table]
    return deps

def get_imported_symbols(lib: Path) -> dict[str, list[str]]:
    file = PEFile(lib)
    with file.open_file_handle():
        symbols = {dll.name: [entry.symbol for entry in lookup_entries] for dll, lookup_entries in zip(file.idata.directory_table, file.idata.import_lookup_table)}
    return symbols
