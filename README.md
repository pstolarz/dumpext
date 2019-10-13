WinDbg PE files dumping library
===============================

This is a WinDbg debugger extension library providing various tools to analyze,
dump and fix (restore) Microsoft Portable Executable files for both 32 (PE) and
64-bit (PE+) platforms. The library is intended to be used by advanced reverse
engineers and malware analysts with their work with malicious software, packers
or viruses.

Features
--------

dumpext provides a rich set of features like:

 - Support for both 32/64-bit PE files formats,
 - Informations related to virtually all PE files details like headers, sections,
   exports, imports (including delayed and bound), thread local storage (TLS),
   relocations, resources tree, exception specification and more...
 - Offset specific informations like memory address to RVA, owning module, file
   pointer etc.
 - Support for PE CRC restore,
 - Support for originally bound imports restore,
 - Various heuristic scans (IAT/IDT) for corrupted/destroyed imports,
 - IDT table localization,
 - Imports tables fixing with full forwarders support,
 - Resources fixing,
 - Various PE headers optimizations and fixing methods (useful for advanced
   packers which may remove some crucial PE file information when they are no
   more needed after the loading phase),
 - Dumping fixed PE file or part of the file (sections) into a file.
 - And much more...

The features may be divided into two sets:

 - Informational: `!dump_pe_info`, `!dump_offset_info`, which are useful for wide
   range of reverse engineers not specifically interested in the PE packers area,
 - Executive: the rest of commands; devoted mainly for PE packers analysts and
   malware reverse engineers working with malicious software using such packers
   (or other methods of PE files protections).

The library has been used for many years by the author to defeat many various PE
files packers (e.g. infamous ASProtect).

dumpext help command output
---------------------------

    dumpext: PE files fix, dump & analysis

    dump_imp_scan iat [-w] [[-s *|n]|[-a|-r addr -l len]] [mod_base]
        IAT imports scanning at specified memory range or of a given module with a
        base mod_base. This is the most generic method for imports scanning.
        -s,r,a,l: Scanning range specification, that is a section number ('*' denotes
            all sections) or a memory range specified by an address or rva.
        -w: Write resolved imports to the config file.
    dump_imp_scan idt [-w] [-a|-r addr [-l len]] [mod_base]
        IDT imports scanning at specified address of the IDT table or of a given
        module with a base mod_base. This command may be used only if IDT location
        is known and the IDT is not corrupted.
        -a,r,l: Specifies an address or rva of the IDT table with an optional length
            constraint.
        -w: Write resolved imports to the config file.

    dump_pe [-s *|n] [mod_base]
        Dump a module with an address mod_base to a file. The configuration file is
        inspected for parameters controlling the dump (e.g. sections specification,
        various methods of fixing etc.)
        -s: Specifies section to extract into separate file. '*' denotes all sections.

    dump_pe_info [header] [-m] [-h] [-d] [-s] [mod_base]
        Show PE details contained in the headers' part of a module with the address
        mod_base. If no options are provided all PE details except the DOS header
        are printed out.
        -m: DOS header.
        -h: PE headers (file and optional).
        -d: PE directories info.
        -s: Sections table.
    dump_pe_info export|import|bimport|dimport|debug|lconf|rsrc|tls|reloc|except
                 [-c|-C] [-x] [-v|-V] [-a|-r addr [-l len]] [mod_base]
        Show PE directory details at specified addr or of a given module with a base
        mod_base.
        -c,C: {rsrc} Show resource capacity details (-c); exclusively (-C).
        -x: {import} Use the imports spec. format of the config file in the output.
        -v,V: {except} Show verbose (-v) and even more verbose (-V) exception table
            details. All the provided informations are platform specific.
        -a,r: {all cases} Specifies an address or rva of the directory.
        -l: {import,bimport,dimport,reloc,except} An optional length constraint.

    dump_offset_info [-v] {-a addr}|{-f ftpr [mod_base]}
        Show address or file pointer details.
        -a: Address details.
        -f: File pointer details.
        -v: Show virtual memory details.

    dump_sects_chrt [-c] [mod_base]
        Analyse PE headers to recognize sections names and characteristics. Show
        the result in the format ready to use in the configuration file. Useful for
        packers destroying mentioned data.
        -c: Read and take into account the configuration (PE headers, sections,
            directories).

    dump_serach idt [-x] [[-s *|n]|[-a|-r addr -l len]] [mod_base]
        Search for and analyse the IDT table with IAT addresses matching the ones
        specified in the imports spec. in the config file. The command shall be used
        for searching destination location of the fixed imports with not modified
        IDT table.
        -s,r,a,l: Searching range specification, that is a section number ('*'
            denotes all sections) or a memory range specified by an address or rva.
        -x: Silent mode. In case of successful search the result is printed in the
            format used by the configuration file.

    dump_conf [conf_file]
        Set configuration file to conf_file. If the file is not specified the current
        configuration file is displayed.

    help
        Show this help.

Compiling and Installing
------------------------

Prerequisites:

 - MS SDK with `cl`, `link` and `nmake`; no need for MS Visual Studio,
 - Debugging Tools for Windows with its SDK,

Compilation:

Set required building environment depending on your target platform (x86/x64,
debug/release etc.) by calling MS SDK's `SetEnv.Cmd` script with proper arguments
and make the library:

    nmake

The result is `dumpext.dll` library located in the sources directory. Install it
by:

    nmake install

Loading and some simple examples
--------------------------------

I. Loading:

    0:000> .load dumpext

II. Help info:

    0:000> !dumpext.help

III. PE headers details. Example of usage for 64-bit `notepad.exe` (the output
is printed in the dumpext's configuration file format):

    0:000> !dump_pe_info notepad
    INFO: Base address of the module: 0x00000000ffd50000 [notepad.exe]

    [file_header]
    Machine = 0x8664   ; x64
    NumberOfSections = 0x0006
    TimeDateStamp = 0x4A5BC9B3
    PointerToSymbolTable = 0x00000000
    NumberOfSymbols = 0x00000000
    SizeOfOptionalHeader = 0x00F0
    Characteristics = 0x0022   ; exe|big_addr_aware

    [optional_header]
    Magic = 0x020B   ; PE32+
    MajorLinkerVersion = 0x09
    MinorLinkerVersion = 0x00
    SizeOfCode = 0x0000A800
    SizeOfInitializedData = 0x00025800
    SizeOfUninitializedData = 0x00000000
    AddressOfEntryPoint = 0x00003570   ; addr: 0x00000000FFD53570, section 1
    BaseOfCode = 0x00001000   ; addr: 0x00000000FFD51000, section 1
    ImageBase = 0x00000000FFD50000
    SectionAlignment = 0x00001000
    FileAlignment = 0x00000200
    MajorOperatingSystemVersion = 0x0006
    MinorOperatingSystemVersion = 0x0001
    MajorImageVersion = 0x0006
    MinorImageVersion = 0x0001
    MajorSubsystemVersion = 0x0006
    MinorSubsystemVersion = 0x0001
    Win32VersionValue = 0x00000000
    SizeOfImage = 0x00035000
    SizeOfHeaders = 0x00000600
    CheckSum = 0x00000000
    Subsystem = 0x0002   ; win gui
    DllCharacteristics = 0x8140   ; dyn_base|nx_compat|term_aware
    SizeOfStackReserve = 0x0000000000080000
    SizeOfStackCommit = 0x0000000000011000
    SizeOfHeapReserve = 0x0000000000100000
    SizeOfHeapCommit = 0x0000000000001000
    LoaderFlags = 0x00000000
    NumberOfRvaAndSizes = 0x00000010

    [directories]
    ExportTab.rva = 0x00000000
    ExportTab.size = 0x00000000
    ImportTab.rva = 0x0000CFF8   ; addr: 0x00000000FFD5CFF8, section 2
    ImportTab.size = 0x0000012C
    ResourceTab.rva = 0x00014000   ; addr: 0x00000000FFD64000, section 5
    ResourceTab.size = 0x0001F160
    ExceptionTab.rva = 0x00013000   ; addr: 0x00000000FFD63000, section 4
    ExceptionTab.size = 0x000006B4
    CertificateTab.rva = 0x00000000
    CertificateTab.szie = 0x00000000
    BaseRelocTab.rva = 0x00034000   ; addr: 0x00000000FFD84000, section 6
    BaseRelocTab.size = 0x000000B8
    Debug.rva = 0x0000B710   ; addr: 0x00000000FFD5B710, section 1
    Debug.size = 0x00000038
    Architecture.rva = 0x00000000
    Architecture.size = 0x00000000
    GlobalPtr.rva = 0x00000000
    GlobalPtr.size = 0x00000000
    TLSTab.rva = 0x00000000
    TLSTab.size = 0x00000000
    LoadConfigTab.rva = 0x00000000
    LoadConfigTab.size = 0x00000000
    BoundImportTab.rva = 0x000002E0   ; addr: 0x00000000FFD502E0, header
    BoundImportTab.size = 0x00000138
    IAT.rva = 0x0000C000   ; addr: 0x00000000FFD5C000, section 2
    IAT.size = 0x000007F0
    DelayImportDesc.rva = 0x00000000
    DelayImportDesc.size = 0x00000000
    CLRRuntimeHeader.rva = 0x00000000
    CLRRuntimeHeader.size = 0x00000000
    Reserved.rva = 0x00000000
    Reserved.size = 0x00000000

    [sections]
    1.Name = .text
    1.VirtualSize = 0x0000A770
    1.VirtualAddress = 0x00001000   ; addr: 0x00000000ffd51000
    1.SizeOfRawData = 0x0000A800
    1.PointerToRawData = 0x00000600
    1.PointerToRelocations = 0x00000000
    1.PointerToLinenumbers = 0x00000000
    1.NumberOfRelocations = 0x0000
    1.NumberOfLinenumbers = 0x0000
    1.Characteristics = 0x60000020   ; code|exec|read
    2.Name = .rdata
    2.VirtualSize = 0x00003160
    2.VirtualAddress = 0x0000C000   ; addr: 0x00000000ffd5c000
    2.SizeOfRawData = 0x00003200
    2.PointerToRawData = 0x0000AE00
    2.PointerToRelocations = 0x00000000
    2.PointerToLinenumbers = 0x00000000
    2.NumberOfRelocations = 0x0000
    2.NumberOfLinenumbers = 0x0000
    2.Characteristics = 0x40000040   ; init_data|read
    3.Name = .data
    3.VirtualSize = 0x00002844
    3.VirtualAddress = 0x00010000   ; addr: 0x00000000ffd60000
    3.SizeOfRawData = 0x00001800
    3.PointerToRawData = 0x0000E000
    3.PointerToRelocations = 0x00000000
    3.PointerToLinenumbers = 0x00000000
    3.NumberOfRelocations = 0x0000
    3.NumberOfLinenumbers = 0x0000
    3.Characteristics = 0xC0000040   ; init_data|read|write
    4.Name = .pdata
    4.VirtualSize = 0x000006B4
    4.VirtualAddress = 0x00013000   ; addr: 0x00000000ffd63000
    4.SizeOfRawData = 0x00000800
    4.PointerToRawData = 0x0000F800
    4.PointerToRelocations = 0x00000000
    4.PointerToLinenumbers = 0x00000000
    4.NumberOfRelocations = 0x0000
    4.NumberOfLinenumbers = 0x0000
    4.Characteristics = 0x40000040   ; init_data|read
    5.Name = .rsrc
    5.VirtualSize = 0x0001F160
    5.VirtualAddress = 0x00014000   ; addr: 0x00000000ffd64000
    5.SizeOfRawData = 0x0001F200
    5.PointerToRawData = 0x00010000
    5.PointerToRelocations = 0x00000000
    5.PointerToLinenumbers = 0x00000000
    5.NumberOfRelocations = 0x0000
    5.NumberOfLinenumbers = 0x0000
    5.Characteristics = 0x40000040   ; init_data|read
    6.Name = .reloc
    6.VirtualSize = 0x000000B8
    6.VirtualAddress = 0x00034000   ; addr: 0x00000000ffd84000
    6.SizeOfRawData = 0x00000200
    6.PointerToRawData = 0x0002F200
    6.PointerToRelocations = 0x00000000
    6.PointerToLinenumbers = 0x00000000
    6.NumberOfRelocations = 0x0000
    6.NumberOfLinenumbers = 0x0000
    6.Characteristics = 0x42000040   ; init_data|discardable|read

IV. Imports details. Example of usage for 64-bit `notepad.exe` (trimmed output):

    0:000> !dump_pe_info import notepad
    INFO: Base address of the module: 0x00000000ffd50000 [notepad.exe]
    INFO: IDT table at: 0x00000000ffd5cff8
    INFO: RVA provided in [], 'h:' denotes hints

    0x00000000ffd5cff8[0x0000CFF8] ADVAPI32.dll IDT Entry:
      ILT at:          0x00000000ffd5d1e8[0x0000D1E8]
      Timestamp:       0xFFFFFFFF   ; new-type bind
      Forwarder chain: 0xFFFFFFFF
      Module name at:  0x00000000ffd5d1d4[0x0000D1D4]
      IAT at:          0x00000000ffd5c000[0x0000C000]
     Imports:
      0x000007fefee047b0: 0x00000000ffd5d9d8[0x0000D9D8] h:0x027E RegSetValueExW
      0x000007fefee0f050: 0x00000000ffd5d9ea[0x0000D9EA] h:0x026E RegQueryValueExW
      0x000007fefee047e0: 0x00000000ffd5d9fe[0x0000D9FE] h:0x023C RegCreateKeyW
      0x000007fefee14de0: 0x00000000ffd5da0e[0x0000DA0E] h:0x0230 RegCloseKey
      0x000007fefee14db0: 0x00000000ffd5da1c[0x0000DA1C] h:0x0261 RegOpenKeyExW
      0x000007fefee14df0: 0x00000000ffd5da2c[0x0000DA2C] h:0x0180 IsTextUnicode
      0x000007fefee0ad44: 0x00000000ffd5da3c[0x0000DA3C] h:0x0057 CloseServiceHandle
      0x000007fefedfe7c8: 0x00000000ffd5da52[0x0000DA52] h:0x01F9 OpenSCManagerW
      0x000007fefedfe7e0: 0x00000000ffd5da64[0x0000DA64] h:0x01FB OpenServiceW
      0x000007fefedfec1c: 0x00000000ffd5da74[0x0000DA74] h:0x0224 QueryServiceConfigW
    ...

V. Export details. Example of usage for 64-bit `kernel32.dll` (trimmed output):

    0:000> !dump_pe_info export kernel32
    INFO: Base address of the module: 0x0000000076ba0000 [C:\Windows\system32\kernel32.dll]
    INFO: Export Directory at: 0x0000000076c3fffc
    INFO: RVA provided in [], '#' precedes ordinals, 'h:' denotes hints

    0x0000000076c3fffc[0x0009FFFC] KERNEL32.dll Export Directory:
      Characteristics:      0x00000000
      Timestamp:            0x556354C0
      Major version:        0x0000
      Minor version:        0x0000
      Module name at:       0x0000000076c43684[0x000A3684]
      Ordinal base:         0x00000001
      Address tab. entries: 0x00000570
      Number of name ptrs:  0x00000570
      Export addr table at: 0x0000000076c40024[0x000A0024]
      Name ptrs table at:   0x0000000076c415e4[0x000A15E4]
      Ordinals table at:    0x0000000076c42ba4[0x000A2BA4]
     Exports:
      0x0000000076c4a1c0[0x000AA1C0]: #0x0001 h:0x0000 0x0000000076c43691[0x000A3691] AcquireSRWLockExclusive -> NTDLL.RtlAcquireSRWLockExclusive
      0x0000000076c4a1e1[0x000AA1E1]: #0x0002 h:0x0001 0x0000000076c436a9[0x000A36A9] AcquireSRWLockShared -> NTDLL.RtlAcquireSRWLockShared
      0x0000000076ba3c80[0x00003C80]: #0x0003 h:0x0002 0x0000000076c436be[0x000A36BE] ActivateActCtx
      0x0000000076c06a10[0x00066A10]: #0x0004 h:0x0003 0x0000000076c436cd[0x000A36CD] AddAtomA
      0x0000000076c069b0[0x000669B0]: #0x0005 h:0x0004 0x0000000076c436d6[0x000A36D6] AddAtomW
    ...

VI. Resources tree details (trimmed output):

    0:000> !dump_pe_info rsrc notepad
    INFO: Base address of the module: 0x00000000ffd50000 [notepad.exe]
    INFO: Resources at: 0x00000000ffd64000
    INFO: RVA provided in [], '#' precedes numeric ids

    0x00000000ffd64000[0x00014000] RootDir
      Characteristics:0x00000000
      Timestamp:      0x00000000
      Major version:  0x0000
      Minor version:  0x0000
      Total entries:  0x0001+0x0005   ; names+ids
     Types:
    .1  0x00000000ffd64000+0x0040[0x00014040] TypeDir "MUI"; name at: 0x00000000ffd64000+0x0400[0x00014400]
          Characteristics:0x00000000
          Timestamp:      0x00000000
          Major version:  0x0000
          Minor version:  0x0000
          Total entries:  0x0000+0x0001   ; names+ids
         Names/IDs:
    .1.1    0x00000000ffd64000+0x0130[0x00014130] NameDir #0x0001
              Characteristics:0x00000000
              Timestamp:      0x00000000
              Major version:  0x0000
              Minor version:  0x0000
              Total entries:  0x0000+0x0001   ; names+ids
             Instances [per language]:
    .1.1.1      0x00000000ffd64000+0x02E0[0x000142E0] LangData #0x0409 en-us
                  Data at:  0x00000000ffd83070[0x00033070]
                  Size:     0x000000F0
                  Code page:0x00000000
                  Reserved: 0x00000000
    .2  0x00000000ffd64000+0x0058[0x00014058] TypeDir #0x0002 RT_BITMAP
          Characteristics:0x00000000
          Timestamp:      0x00000000
          Major version:  0x0000
          Minor version:  0x0000
          Total entries:  0x0000+0x0001   ; names+ids
         Names/IDs:
    .2.1    0x00000000ffd64000+0x0148[0x00014148] NameDir #0xC809
              Characteristics:0x00000000
              Timestamp:      0x00000000
              Major version:  0x0000
              Minor version:  0x0000
              Total entries:  0x0000+0x0001   ; names+ids
             Instances [per language]:
    .2.1.1      0x00000000ffd64000+0x02F0[0x000142F0] LangData #0x0409 en-us
                  Data at:  0x00000000ffd648a8[0x000148A8]
                  Size:     0x0000561A
                  Code page:0x00000000
                  Reserved: 0x00000000
    ...

VII. Address  details:

    0:000> !dump_offset_info -v -a 0x00000000ffd83070
    Address 0x00000000ffd83070 details:
      Module base:  0x00000000ffd50000
      Image name:   notepad.exe
      RVA:          0x00033070
      Contained in: sect 5 [.rsrc], sect mem range: 0x00000000ffd64000..0x00000000ffd8315f
      File ptr:     0x0002F070
    Virtual memory info:
      Base address: 0x00000000ffd83000
      Alloc base:   0x00000000ffd50000
      Alloc protect:0x00000080   ; PAGE_EXECUTE_WRITECOPY
      Region size:  0x0000000000002000
      State:        0x00001000   ; MEM_COMMIT
      Protect:      0x00000002   ; PAGE_READONLY
      Type:         0x01000000   ; SEC_IMAGE

    0:000> !dump_offset_info -v -a 0x0000000076c40024
    Address 0x0000000076c40024 details:
      Module base:  0x0000000076ba0000
      Image name:   C:\Windows\system32\kernel32.dll
      RVA:          0x000A0024
      Contained in: sect 2 [.rdata], sect mem range: 0x0000000076c3c000..0x0000000076ca98c7
      File ptr:     0x0009F624
    Virtual memory info:
      Base address: 0x0000000076c40000
      Alloc base:   0x0000000076ba0000
      Alloc protect:0x00000080   ; PAGE_EXECUTE_WRITECOPY
      Region size:  0x000000000006a000
      State:        0x00001000   ; MEM_COMMIT
      Protect:      0x00000002   ; PAGE_READONLY
      Type:         0x01000000   ; SEC_IMAGE

VIII. Dump arbitrary PE file, which has been already loaded into the debugger and
not protected by a packer. Example of an output for 64-bit `explorer.exe`:

    0:000> !dump_pe explorer
    INFO: Base address of the dumped module: 0x00000000ff1c0000 [explorer.exe]
    INFO: Updated optional_header/SizeOfCode from 0x000B7C00 to 0x000B8000
    INFO: Updated optional_header/SizeOfInitializedData from 0x00205600 to 0x00207000
    INFO: PE headers have been dumped to the output file
    INFO: PE sections have been dumped to the output file
    INFO: IAT table successfully fixed
    INFO: PE checksum written: 0x002C1D54
    INFO: Bound imports:
     Import ADVAPI32.dll, Timestamp: 0x556365E3 with 1 forwarder(s)
      Forwarder ntdll.DLL, Timestamp: 0x556366F2
     Import KERNEL32.dll, Timestamp: 0x556366FC with 1 forwarder(s)
      Forwarder ntdll.DLL, Timestamp: 0x556366F2
     Import GDI32.dll, Timestamp: 0x54F7E29C
     Import USER32.dll, Timestamp: 0x4CE7C9F1 with 1 forwarder(s)
      Forwarder ntdll.DLL, Timestamp: 0x556366F2
     Import msvcrt.dll, Timestamp: 0x4EEB033F with 1 forwarder(s)
      Forwarder ntdll.DLL, Timestamp: 0x556366F2
     Import ntdll.DLL, Timestamp: 0x556366F2
     Import SHLWAPI.dll, Timestamp: 0x4CE7C9AB
     Import SHELL32.dll, Timestamp: 0x54DD89C7
     Import ole32.dll, Timestamp: 0x4CE7C92C
     Import OLEAUT32.dll, Timestamp: 0x54754E4A
     Import EXPLORERFRAME.dll, Timestamp: 0x4CE7C6A8
     Import UxTheme.dll, Timestamp: 0x4A5BE093
     Import POWRPROF.dll, Timestamp: 0x4A5BE062
     Import dwmapi.dll, Timestamp: 0x4A5BDF27
     Import slc.dll, Timestamp: 0x4A5BE063
     Import gdiplus.dll, Timestamp: 0x55346E73
     Import Secur32.dll, Timestamp: 0x55636730 with 1 forwarder(s)
      Forwarder SSPICLI.DLL, Timestamp: 0x55636743
     Import RPCRT4.dll, Timestamp: 0x53C339EE
     Import PROPSYS.dll, Timestamp: 0x4CE7C94A
    INFO: Imports have been bound
    INFO: Dumping process finished with success

The dumped `explorer.exe` image is now located in `WINDBG_DIR\dump.out`. Try to
execute it.

IX. IAT scanning example for 32-bit `kernel32.dll`.

    0:000> !dump_pe_info imp kernel32
    INFO: Base address of the module: 0x7c800000 [C:\WINDOWS\system32\kernel32.dll]
    INFO: IDT table at: 0x7c882600
    INFO: RVA provided in [], 'h:' denotes hints

    0x7c882600[0x00082600] ntdll.dll IDT Entry:
      ILT at:          0x7c882634[0x00082634]
      Timestamp:       0x00000000   ; not bound
      Forwarder chain: 0x00000000
      Module name at:  0x7c882628[0x00082628]
      IAT at:          0x7c801000[0x00001000]
    ...

So, the IAT is located at 0x7c801000, RVA:0x00001000.
Scan the `kernel32` module mapped memory for the IAT location:

    0:000> !dump_imp_scan iat kernel32
    INFO: Base address of the module being scanned: 0x7c800000 [C:\WINDOWS\system32\kernel32.dll]
    INFO: IAT scanning starts at: 0x7c801000, size constraint: 0x0624
    ...
    INFO: Resolved imports are:
    [imports]
    1 = ntdll.dll
    1.iat_rva = 0x00001000
    1.1 = _wcsnicmp
    1.2 = NtFsControlFile
    1.3 = NtCreateFile
    1.4 = RtlAllocateHeap
    ...

The IAT was correctly located by the scanner (RVA:0x00001000). Note, the IAT
scanning result is presented in the dumpext's configuration file format, ready
to be used inside the configuration file to help PE file restoring process
automation.

The `!dump_imp_scan` command automatically detects most proper section to scan
for imports by inspecting PE sections table and PE directory (try
`!dump_pe_info -sd` to discover the underlaying logic). The logic is not always
accurate, therefore `!dump_imp_scan` allows to specify section(s) intended to be
scanned (`-s` option).

Configuration file
------------------

`!dump_pe`, `!dump_serach idt` and `!dump_sects_chrt` (optionally) commands use
a configuration file which controls their work. By default the file is looked in
the same directory as the extension library under `dumpext.conf` name. This can
be changed using `!dump_conf` command.

Refer to the `dumpext.conf` file in the source directory for more details.

License
-------
GNU GENERAL PUBLIC LICENSE v2. See LICENSE file for details.
