const std = @import("std");
const windows = std.os.windows;
const HANDLE = std.os.windows.HANDLE;
const FARPROC = windows.FARPROC;
const HEAP_ZERO_MEMORY = 0x00000008;
const IMAGE_DOS_SIGNATURE = 0x5A4D;
const IMAGE_NT_SIGNATURE = 0x0000_4550;
const IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
const IMAGE_FILE_DLL = 0x2000;
const IMAGE_SUBSYSTEM_NATIVE = 1;
const IMAGE_FILE_MACHINE_I386 = 0x014c;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;
const IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
const IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
const IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;
const IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
const IMAGE_DIRECTORY_ENTRY_TLS = 9;
const IMAGE_DIRECTORY_ENTRY_IAT = 12;
const IMAGE_SCN_MEM_READ = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE = 0x8000_0000;
const IMAGE_SCN_MEM_EXECUTE = 0x2000_0000;

pub extern "kernel32" fn GetProcAddress(hModule: windows.HMODULE, lpProcName: windows.LPCSTR) callconv(windows.WINAPI) FARPROC;
pub extern "kernel32" fn GetModuleHandleA(lpModuleName: windows.LPCSTR) callconv(windows.WINAPI) windows.HMODULE;

const IMAGE_DOS_HEADER = extern struct {
    e_magic: windows.WORD, // Magic number (should be "MZ" - 0x5A4D)
    e_cblp: u16, // Bytes on last page of file
    e_cp: u16, // Pages in file
    e_crlc: u16, // Relocations
    e_cparhdr: u16, // Size of header in paragraphs
    e_minalloc: u16, // Minimum extra paragraphs needed
    e_maxalloc: u16, // Maximum extra paragraphs needed
    e_ss: u16, // Initial (relative) SS value
    e_sp: u16, // Initial SP value
    e_csum: u16, // Checksum
    e_ip: u16, // Initial IP value
    e_cs: u16, // Initial (relative) CS value
    e_lfarlc: u16, // File address of relocation table
    e_ovno: u16, // Overlay number
    e_res: [4]u16, // Reserved words
    e_oemid: u16, // OEM identifier
    e_oeminfo: u16, // OEM information
    e_res2: [10]u16, // Reserved words
    e_lfanew: u32, // File address of new exe header
};

pub const IMAGE_NT_HEADERS64 = extern struct {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

pub const IMAGE_FILE_HEADER = extern struct {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
};

pub const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: u32,
    Size: u32,
};

pub const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};
pub const IMAGE_EXPORT_DIRECTORY = extern struct {
    Characteristics: u32, // Reserved, must be 0
    TimeDateStamp: u32, // Time and date the export data was created
    MajorVersion: u16, // Major version number
    MinorVersion: u16, // Minor version number
    Name: u32, // RVA of the ASCII string containing the name of the DLL
    Base: u32, // Starting ordinal number (usually 1)
    NumberOfFunctions: u32, // Number of entries in the Export Address Table
    NumberOfNames: u32, // Number of entries in the Name Pointer Table
    AddressOfFunctions: u32, // RVA of the Export Address Table
    AddressOfNames: u32, // RVA of the Export Names Table
    AddressOfNameOrdinals: u32, // RVA of the Ordinal Table
};
const IMAGE_SECTION_HEADER = extern struct {
    Name: [8]u8, // Section name
    VirtualSize: u32, // Size of section when loaded into memory
    VirtualAddress: u32, // RVA of section start in memory
    SizeOfRawData: u32, // Size of initialized data on disk
    PointerToRawData: u32, // File pointer to section's first page
    PointerToRelocations: u32, // File pointer to section's relocations
    PointerToLinenumbers: u32, // File pointer to section's line numbers
    NumberOfRelocations: u16, // Number of relocations
    NumberOfLinenumbers: u16, // Number of line numbers
    Characteristics: u32, // Flags describing section's characteristics

    // Common section characteristic flags
    pub const IMAGE_SCN_CNT_CODE: u32 = 0x00000020; // Section contains executable code
    pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040; // Section contains initialized data
    pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080; // Section contains uninitialized data
    pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000; // Section can be executed
    pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000; // Section can be read
    pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000; // Section can be written to

};

fn GetProcAddressReplacement(hModule: HANDLE, lpApiName: windows.LPCSTR) !windows.FARPROC {
    const pBase: [*]u8 = @ptrCast(@alignCast(hModule));
    const pImgDosHdr: *IMAGE_DOS_HEADER = @ptrCast(@alignCast(pBase));
    if (pImgDosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        return error.IMAGE_DOS_SIGNATURE_MISMATCH;
    }

    const pImgNtHdrs: *IMAGE_NT_HEADERS64 = @ptrCast(@alignCast(pBase + pImgDosHdr.e_lfanew));
    const ImgOptHdr: IMAGE_OPTIONAL_HEADER64 = pImgNtHdrs.OptionalHeader;
    const pImgExportDir: *IMAGE_EXPORT_DIRECTORY = @ptrCast(@alignCast(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
    const FunctionNameArray: [*]windows.DWORD = @ptrCast(@alignCast(pBase + pImgExportDir.AddressOfNames));
    const FunctionAddressArray: [*]windows.DWORD = @ptrCast(@alignCast(pBase + pImgExportDir.AddressOfFunctions));
    const FunctionOrdinalArray: [*]u16 = @ptrCast(@alignCast(pBase + pImgExportDir.AddressOfNameOrdinals));
    var i: usize = 0;
    while (i < pImgExportDir.NumberOfFunctions) : (i += 1) {
        const pFunctionName: [*:0]const u8 = @ptrCast(@alignCast(pBase + FunctionNameArray[i]));
        if (std.mem.eql(u8, std.mem.span(lpApiName), std.mem.span(pFunctionName))) {
            const ordinal = FunctionOrdinalArray[i];
            const functionRva = FunctionAddressArray[ordinal];
            return @ptrCast(@alignCast(pBase + functionRva));
        }
    }

    std.debug.print("[i] Catcher and the Rye: {any}\n", .{lpApiName});
    return error.FUCKED;
}

pub fn main() !void {
    const ntdll_str = try std.unicode.utf8ToUtf16LeAllocZ(std.heap.page_allocator, "ntdll.dll");
    const ntdll_func = "NtAllocateUuids";
    defer std.heap.page_allocator.free(ntdll_str);
    std.debug.print("[i] Original GetProcAddress: {p}\n", .{GetProcAddress(windows.kernel32.GetModuleHandleW(ntdll_str).?, ntdll_func)});
    std.debug.print("[i] GetProcAddress Replacement: {any}\n", .{try GetProcAddressReplacement(windows.kernel32.GetModuleHandleW(ntdll_str).?, ntdll_func)});
}
