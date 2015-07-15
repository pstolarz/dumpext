/*
   Copyright (c) 2015 Piotr Stolarz
   dumpext: PE files fix, dump & analysis WinDbg extension

   Distributed under the GNU General Public License (the License)
   see accompanying file LICENSE for details.

   This software is distributed WITHOUT ANY WARRANTY; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the License for more information.
 */

#include "common.h"
#include "config.h"
#include "imports.h"
#include "resrc.h"
#include "except.h"

/* DLL entry point */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    BOOL ret=TRUE;

    switch(fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        set_tls_i(TlsAlloc());
        if (get_tls_i()!=TLS_OUT_OF_INDEXES) init_config(hinstDLL);
        else ret=FALSE;
        break;

    case DLL_PROCESS_DETACH:
        if (get_tls_i()!=TLS_OUT_OF_INDEXES) TlsFree(get_tls_i());
        break;
    }

    return ret;
}

/* Extension initialization */
HRESULT CALLBACK
DebugExtensionInitialize(PULONG Version, PULONG Flags)
{
    *Version = DEBUG_EXTENSION_VERSION(1, 0);
    *Flags = 0;

    return S_OK;
}

/* Recognize command string 'p_cmd' in arguments input 'args'. Min recognized
   length of the command is passed by 'min_len'. If a command has been recognized
   TRUE is returned and 'p_args' will point just after the recognized command
   in 'args'.
 */
static BOOL is_cmd(PCSTR args, const char *p_cmd, size_t min_len, PCSTR *p_args)
{
    BOOL ret=FALSE;

    *p_args=args;

    size_t i, cmd_len;
    for (i=0; isspace(args[i]); i++);
    for (cmd_len=0; args[i+cmd_len] && !isspace(args[i+cmd_len]); cmd_len++);

    BOOL cmd_match = (!cmd_len ? TRUE : !strncmp(&args[i], p_cmd, cmd_len));

    if (!min_len && !cmd_match)
    {
        /* for default command and not matching input: if the input indicates
           the command's flags (staring by '-') then the command matches, since
           it seems it has been omitted; else some other command is provided
           - return FALSE */
        ret = args[i]=='-';
    } else
    if (cmd_match && cmd_len>=min_len) {
        i += cmd_len;
        *p_args = &args[i];
        ret=TRUE;
    }
    return ret;
}

/* Get module base addr form *p_args (the pointer is changed after the read
   accordingly). If the base address is not specified as an argument take the
   mod base owning the address 'addr' if 'addr' is not NULL. Otherwise take the
   first exe module starting from index 0. The name of image file name is
   written under 'pc_img_name'. This buf must be at least MAX_PATH+1 long.

   Returns 0 if error.
 */
static ULONG64 get_mod_base(PCSTR *p_args, ULONG64 addr, char *pc_img_name)
{
    ULONG64 mod_base=0;
    IDebugSymbols *DebugSymbols=NULL;
    IDebugSymbols2 *DebugSymbols2=NULL;

    if (!get_expression(*p_args, &mod_base, p_args))
    {
        mod_base=0;

        if ((get_client()->QueryInterface(
            __uuidof(IDebugSymbols), (void **)&DebugSymbols))!=S_OK) goto finish;

        if (addr) {
            if (DebugSymbols->GetModuleByOffset(addr, 0, NULL, &mod_base)!=S_OK)
                mod_base=0;
        }
        if (!mod_base)
        {
            ULONG ld_mods_n, uld_mods_n;
            if (DebugSymbols->GetNumberModules(&ld_mods_n, &uld_mods_n)!=S_OK)
                goto finish;

            UINT i;
            ULONG64 mod_base_1st=0;
            for (i=0; i<ld_mods_n; i++)
            {
                if (DebugSymbols->GetModuleByIndex(i, &mod_base)!=S_OK)
                    continue;

                if (!mod_base_1st) mod_base_1st=mod_base;

                IMAGE_DOS_HEADER dos_hdr;
                image_nt_headers_t nt_hdrs;
                if (!read_pe_headers(mod_base, &dos_hdr, &nt_hdrs, NULL, FALSE))
                    continue;

                WORD fchr=get_16uint_le(&get_FileHeader(&nt_hdrs).Characteristics);
                if (fchr&IMAGE_FILE_EXECUTABLE_IMAGE && !(fchr&IMAGE_FILE_DLL))
                    break;
            }

            if (i>=ld_mods_n) {
                mod_base=mod_base_1st;
                if (!mod_base_1st) goto finish;
            }
        }
    }

    if (pc_img_name)
    {
        ULONG img_name_sz=0;
        *pc_img_name=0;

        if ((get_client()->QueryInterface(
            __uuidof(IDebugSymbols2), (void **)&DebugSymbols2))!=S_OK) goto finish;

        if (DebugSymbols2->GetModuleNameString(DEBUG_MODNAME_IMAGE,
            DEBUG_ANY_ID, mod_base, pc_img_name, MAX_PATH+1, &img_name_sz)==S_OK
            && img_name_sz>0)
        {
            pc_img_name[MAX_PATH]=0;
        } else
            *pc_img_name=0;
    }

finish:
    if (DebugSymbols2) DebugSymbols2->Release();
    if (DebugSymbols) DebugSymbols->Release();
    return mod_base;
}

/* dump_imp_scan family of commands */
HRESULT CALLBACK
dump_imp_scan(PDEBUG_CLIENT4 Client, PCSTR args)
{
    HRESULT ret=E_FAIL;
    set_client(Client);

    flag_desc_t flags_dsc_iat[] =
        {{'w', FALSE}, {'s', TRUE}, {'a', TRUE}, {'r', TRUE}, {'l', TRUE}};
    flag_desc_t flags_dsc_idt[] =
        {{'w', FALSE}, {'a', TRUE}, {'r', TRUE}, {'l', TRUE}};

    iscan_tpy_t scan_tpy;
    flag_desc_t *p_flags_dsc;
    UINT n_flags;

    if (is_cmd(args, "iat", 2, &args)) {
        scan_tpy=iscan_iat;
        p_flags_dsc=flags_dsc_iat;
        n_flags = sizeof(flags_dsc_iat)/sizeof(flags_dsc_iat[0]);
    } else
    if (is_cmd(args, "idt", 2, &args)) {
        scan_tpy=iscan_idt;
        p_flags_dsc=flags_dsc_idt;
        n_flags = sizeof(flags_dsc_idt)/sizeof(flags_dsc_idt[0]);
    } else goto finish;

    rng_spec_t rng;
    rngspc_rc_t rc = get_range_spec(&args, p_flags_dsc, n_flags, &rng);
    if (rc==rngspc_err) goto finish;

    DWORD flags=0;
    if (p_flags_dsc[0].is_pres) flags|=SCANIMPS_WRITE_CONF;

    ULONG64 rng_addr=NULL;
    if (rc==rngspc_ok && !rng.is_sect && !rng.rng.is_rva) rng_addr=rng.rng.addr;

    char img_name[MAX_PATH+1];
    ULONG64 mod_base = get_mod_base(&args, rng_addr, img_name);
    if (!mod_base || strlen(args)) goto finish;

    info_dbgprintf("Base address of the module being scanned: 0x%p [%s]\n",
        mod_base, img_name);

    scan_imports(
        mod_base, scan_tpy, (rc==rngspc_not_prov ? NULL : &rng), flags);

    ret=S_OK;
finish:
    return ret;
}

/* dump_pe [-s *|n] [mod_base] */
HRESULT CALLBACK
dump_pe(PDEBUG_CLIENT4 Client, PCSTR args)
{
    HRESULT ret=E_FAIL;
    set_client(Client);

    flag_desc_t flags_dsc[] = {{'s', TRUE}};
    UINT n_flags = sizeof(flags_dsc)/sizeof(flags_dsc[0]);

    rng_spec_t rng;
    rngspc_rc_t rc = get_range_spec(&args, flags_dsc, n_flags, &rng);
    if (rc==rngspc_err) goto finish;

    char img_name[MAX_PATH+1];
    ULONG64 mod_base = get_mod_base(&args, NULL, img_name);
    if (!mod_base || strlen(args)) goto finish;

    info_dbgprintf(
        "Base address of the dumped module: 0x%p [%s]\n", mod_base, img_name);

    if (!pe_dump(mod_base, (rc==rngspc_not_prov ? 0 : rng.sect))) goto finish;

    ret=S_OK;
finish:
    return ret;
}

/* dump_pe_info family of commands */
HRESULT CALLBACK
dump_pe_info(PDEBUG_CLIENT4 Client, PCSTR args)
{
    HRESULT ret=E_FAIL;
    PCSTR args_org=args;
    set_client(Client);

    BOOL b_import=FALSE, b_export=FALSE, b_bimport=FALSE, b_dimport=FALSE;
    BOOL b_debug=FALSE, b_lconf=FALSE, b_rsrc=FALSE, b_tls=FALSE, b_reloc=FALSE,
    b_except=FALSE;
    if (!(b_import=is_cmd(args, "import", 1, &args)))
    if (!(b_export=is_cmd(args, "export", 3, &args)))
    if (!(b_bimport=is_cmd(args, "bimport", 1, &args)))
    if (!(b_dimport=is_cmd(args, "dimport", 2, &args)))
    if (!(b_debug=is_cmd(args, "debug", 2, &args)))
    if (!(b_lconf=is_cmd(args, "lconf", 1, &args)))
    if (!(b_rsrc=is_cmd(args, "rsrc", 2, &args)))
    if (!(b_tls=is_cmd(args, "tls", 1, &args)))
    if (!(b_reloc=is_cmd(args, "reloc", 2, &args)))
    if (!(b_except=is_cmd(args, "except", 3, &args)));

    if (b_import || b_export || b_bimport || b_dimport ||
        b_debug || b_lconf || b_rsrc || b_tls || b_reloc ||
        b_except)
    {
        flag_desc_t flags_dsc_rng[] =
            {{'a', TRUE}, {'r', TRUE}};
        flag_desc_t flags_dsc_rng_l[] =
            {{'a', TRUE}, {'r', TRUE}, {'l', TRUE}};
        flag_desc_t flags_dsc_imp[] =
            {{'x', FALSE}, {'a', TRUE}, {'r', TRUE}, {'l', TRUE}};
        flag_desc_t flags_dsc_rsrc[] =
            {{'c', FALSE}, {'C', FALSE}, {'a', TRUE}, {'r', TRUE}};
        flag_desc_t flags_dsc_except[] =
            {{'v', FALSE}, {'V', FALSE}, {'a', TRUE}, {'r', TRUE}, {'l', TRUE}};

        UINT n_flags;
        flag_desc_t *p_flags_dsc;

        if (b_import) {
            p_flags_dsc = flags_dsc_imp;
            n_flags = sizeof(flags_dsc_imp)/sizeof(flags_dsc_imp[0]);
        } else
        if (b_bimport || b_dimport || b_reloc) {
            p_flags_dsc = flags_dsc_rng_l;
            n_flags = sizeof(flags_dsc_rng_l)/sizeof(flags_dsc_rng_l[0]);
        } else
        if (b_export || b_debug || b_lconf || b_tls) {
            p_flags_dsc = flags_dsc_rng;
            n_flags = sizeof(flags_dsc_rng)/sizeof(flags_dsc_rng[0]);
        } else
        if (b_rsrc) {
            p_flags_dsc = flags_dsc_rsrc;
            n_flags = sizeof(flags_dsc_rsrc)/sizeof(flags_dsc_rsrc[0]);
        } else
        if (b_except) {
            p_flags_dsc = flags_dsc_except;
            n_flags = sizeof(flags_dsc_except)/sizeof(flags_dsc_except[0]);
        }

        rng_spec_t rng;
        rngspc_rc_t rc = get_range_spec(&args, p_flags_dsc, n_flags, &rng);
        if (rc==rngspc_err) goto finish;

        ULONG64 rng_addr=NULL;
        if (rc==rngspc_ok && !rng.is_sect && !rng.rng.is_rva)
            rng_addr=rng.rng.addr;

        char img_name[MAX_PATH+1];
        ULONG64 mod_base = get_mod_base(&args, rng_addr, img_name);
        if (!mod_base || strlen(args)) goto finish;

        info_dbgprintf(
            "Base address of the module: 0x%p [%s]\n", mod_base, img_name);

        if (b_import) {
            DWORD flags = 0;
            if (p_flags_dsc[0].is_pres) flags|=PRNTIMP_IMPSPEC;
            print_imports(mod_base, (rc==rngspc_not_prov ? NULL : &rng), flags);
        } else
        if (b_export) {
            print_exports(mod_base, (rc==rngspc_not_prov ? NULL : &rng));
        } else
        if (b_bimport) {
            print_bound_imps(mod_base, (rc==rngspc_not_prov ? NULL : &rng));
        } else
        if (b_dimport) {
            print_delay_imps(mod_base, (rc==rngspc_not_prov ? NULL : &rng));
        } else
        if (b_debug) {
            print_debug(mod_base, (rc==rngspc_not_prov ? NULL : &rng));
        } else
        if (b_lconf) {
            print_lconf(mod_base, (rc==rngspc_not_prov ? NULL : &rng));
        } else
        if (b_rsrc) {
            DWORD flags = 0;
            if (p_flags_dsc[0].is_pres) flags|=PRNTRSRC_CAPAS;
            if (p_flags_dsc[1].is_pres) flags|=PRNTRSRC_CAPAS_ONLY;
            print_rsrc(mod_base, (rc==rngspc_not_prov ? NULL : &rng), flags);
        } else
        if (b_tls) {
            print_tls(mod_base, (rc==rngspc_not_prov ? NULL : &rng));
        } else
        if (b_reloc) {
            print_reloc(mod_base, (rc==rngspc_not_prov ? NULL : &rng));
        } else
        if (b_except) {
            DWORD info_details=PRNTEXCPT_INFO_NORMAL;
            if (p_flags_dsc[1].is_pres) info_details=PRNTEXCPT_INFO_VERBOSE;
            else
            if (p_flags_dsc[0].is_pres) info_details=PRNTEXCPT_INFO_DETAILED;
            print_except(
                mod_base, (rc==rngspc_not_prov ? NULL : &rng), info_details);
        }
    } else
    {
        /* try default "header" command */
        args=args_org;

        /* if the "header command is specified - omit it "*/
        if (is_cmd(args, "header", 1, &args));
        else args=args_org;

        DWORD flags=0;
        flag_desc_t flags_dsc[] =
            {{'m', FALSE}, {'h', FALSE}, {'d', FALSE}, {'s', FALSE}};

        UINT n_flags = sizeof(flags_dsc)/sizeof(flags_dsc[0]);
        size_t rd_sz = read_flags(args, flags_dsc, n_flags);
        args += rd_sz;

        if (flags_dsc[0].is_pres) flags|=PRNTPE_DOS_HEADER;
        if (flags_dsc[1].is_pres) flags|=PRNTPE_PE_HEADERS;
        if (flags_dsc[2].is_pres) flags|=PRNTPE_DIRS;
        if (flags_dsc[3].is_pres) flags|=PRNTPE_SECTS;

        /* default print flags (if not specified) */
        if (!flags) flags = PRNTPE_PE_HEADERS|PRNTPE_DIRS|PRNTPE_SECTS;

        char img_name[MAX_PATH+1];
        ULONG64 mod_base = get_mod_base(&args, NULL, img_name);
        if (!mod_base || strlen(args)) goto finish;

        info_dbgprintf(
            "Base address of the module: 0x%p [%s]\n\n", mod_base, img_name);

        print_pe_details(mod_base, flags);
    }

    ret=S_OK;
finish:
    return ret;
}

/* dump_offset_info [-v] {-a addr}|{-f ftpr [mod_base]} */
HRESULT CALLBACK
dump_offset_info(PDEBUG_CLIENT4 Client, PCSTR args)
{
    HRESULT ret=E_FAIL;
    set_client(Client);

    ULONG64 addr;
    BOOL b_virt_det=FALSE;

    IDebugSymbols *DebugSymbols=NULL;
    IDebugSymbols2 *DebugSymbols2=NULL;

    if ((get_client()->QueryInterface(
        __uuidof(IDebugSymbols), (void **)&DebugSymbols))!=S_OK) goto err;

    flag_desc_t flags_dsc[] = {{'a', TRUE}, {'f', TRUE}, {'v', FALSE}};
    UINT n_flags = sizeof(flags_dsc)/sizeof(flags_dsc[0]);

    size_t rd_sz = read_flags(args, flags_dsc, n_flags);
    args += rd_sz;

    if (flags_dsc[0].is_pres)
    {
        size_t arg_len = flags_dsc[0].arg_len;
        if (!arg_len || strlen(args)) goto err;

        ULONG64 mod_base;

        char c = flags_dsc[0].pc_arg[arg_len];
        flags_dsc[0].pc_arg[arg_len] = 0;
        if (!get_expression(flags_dsc[0].pc_arg, &addr, NULL)) goto err;
        flags_dsc[0].pc_arg[arg_len] = c;

        b_virt_det=TRUE;

        dbgprintf("Address 0x%p details:\n", addr);

        if (DebugSymbols->GetModuleByOffset(addr, 0, NULL, &mod_base)!=S_OK) {
            dbgprintf("  Can not establish the owning module\n");
            goto no_err;
        }

        ULONG img_name_sz=0;
        char img_name[MAX_PATH+1];
        *img_name=0;

        if ((get_client()->QueryInterface(
            __uuidof(IDebugSymbols2), (void **)&DebugSymbols2))==S_OK)
        {
            if (DebugSymbols2->GetModuleNameString(
                DEBUG_MODNAME_IMAGE, DEBUG_ANY_ID, mod_base, img_name,
                sizeof(img_name), &img_name_sz)==S_OK && img_name_sz>0)
            {
                img_name[sizeof(img_name)-1]=0;
            } else
                *img_name=0;
        }

        DWORD rva = ADDR2RVA(addr, mod_base);

        dbgprintf("  Module base:  0x%p\n", mod_base);
        if (*img_name) dbgprintf("  Image name:   %s\n", img_name);
        dbgprintf("  RVA:          0x%08X\n", rva);

        IMAGE_DOS_HEADER dos_hdr;
        image_nt_headers_t nt_hdrs;

        DWORD n_sects;
        ULONG64 sectab_addr;
        IMAGE_SECTION_HEADER sectab[MAX_SECTIONS];

        if (!read_pe_headers(
            mod_base, &dos_hdr, &nt_hdrs, &sectab_addr, TRUE)) goto no_err;

        DWORD hdrs_sz = (nt_hdrs.pe_tpy==pe_32bit ?
            get_32uint_le(&nt_hdrs.hdr.pe32.OptionalHeader.SizeOfHeaders):
            get_32uint_le(&nt_hdrs.hdr.pe64.OptionalHeader.SizeOfHeaders));

        if (0<=rva && rva<hdrs_sz) {
            dbgprintf("  Contained in: header\n");
            dbgprintf("  File ptr:     0x%08X\n", rva);
        } else
        {
            if (!(n_sects=read_sectab(
                &nt_hdrs, sectab_addr, sectab, TRUE, TRUE))) goto no_err;

            DWORD sect_i, rptr;
            if (get_rva_info(sectab, n_sects, rva, &sect_i, NULL, NULL, &rptr))
            {
                char sec_name[IMAGE_SIZEOF_SHORT_NAME+1];
                strncpy(
                    sec_name, (char*)&sectab[sect_i].Name[0], sizeof(sec_name)-1);
                sec_name[sizeof(sec_name)-1] = 0;

                DWORD sec_rva = get_32uint_le(&sectab[sect_i].VirtualAddress);
                DWORD sec_vsz = get_32uint_le(&sectab[sect_i].Misc.VirtualSize);

                dbgprintf(
                    "  Contained in: sect %d [%s], sect mem range: 0x%p..0x%p\n",
                    sect_i+1, sec_name, RVA2ADDR(sec_rva, mod_base),
                    RVA2ADDR(sec_rva+sec_vsz-1, mod_base));

                if (rptr) dbgprintf("  File ptr:     0x%08X\n", rptr);
                else dbgprintf("  Not contained in PE file!\n");
            } else {
                dbgprintf("  Outside sects!\n");
            }
        }
    }
    else if (flags_dsc[1].is_pres)
    {
        size_t arg_len = flags_dsc[1].arg_len;
        if (!arg_len) goto err;

        ULONG64 expr;

        char c = flags_dsc[1].pc_arg[arg_len];
        flags_dsc[1].pc_arg[arg_len] = 0;
        if (!get_expression(flags_dsc[1].pc_arg, &expr, NULL)) goto err;
        flags_dsc[1].pc_arg[arg_len] = c;

        DWORD rptr = (DWORD)expr;
        if (rptr!=expr) {
            err_dbgprintf("File pointer too large\n");
            goto err;
        }

        char img_name[MAX_PATH+1];
        ULONG64 mod_base = get_mod_base(&args, NULL, img_name);
        if (!mod_base || strlen(args)) goto err;

        dbgprintf("File pointer 0x%08X details:\n", rptr);

        dbgprintf("  Module base:  0x%p\n", mod_base);
        if (*img_name) dbgprintf("  Image name:   %s\n", img_name);

        IMAGE_DOS_HEADER dos_hdr;
        image_nt_headers_t nt_hdrs;

        DWORD n_sects;
        ULONG64 sectab_addr;
        IMAGE_SECTION_HEADER sectab[MAX_SECTIONS];

        if (!read_pe_headers(mod_base, &dos_hdr, &nt_hdrs, &sectab_addr, TRUE))
            goto no_err;

        DWORD hdrs_sz = (nt_hdrs.pe_tpy==pe_32bit ?
            get_32uint_le(&nt_hdrs.hdr.pe32.OptionalHeader.SizeOfHeaders):
            get_32uint_le(&nt_hdrs.hdr.pe64.OptionalHeader.SizeOfHeaders));

        if (0<=rptr && rptr<hdrs_sz)
        {
            addr = RVA2ADDR(rptr, mod_base);
            b_virt_det=TRUE;

            dbgprintf("  Contained in: header, mem range: 0x%p..0x%p\n",
                addr, addr+hdrs_sz-1);
            dbgprintf("  Address [RVA]:0x%p [0x%08X]\n", addr, rptr);
        } else
        {
            if (!(n_sects=read_sectab(
                &nt_hdrs, sectab_addr, sectab, TRUE, TRUE))) goto no_err;

            DWORD sect_i, rva;
            if (get_rptr_info(sectab, n_sects, rptr, &sect_i, NULL, &rva))
            {
                char sec_name[IMAGE_SIZEOF_SHORT_NAME+1];
                strncpy(
                    sec_name, (char*)&sectab[sect_i].Name[0], sizeof(sec_name)-1);
                sec_name[sizeof(sec_name)-1] = 0;

                DWORD sec_rva = get_32uint_le(&sectab[sect_i].VirtualAddress);
                DWORD sec_vsz = get_32uint_le(&sectab[sect_i].Misc.VirtualSize);

                dbgprintf(
                    "  Contained in: sect %d [%s], sect mem range: 0x%p..0x%p\n",
                    sect_i+1, sec_name, RVA2ADDR(sec_rva, mod_base),
                    RVA2ADDR(sec_rva+sec_vsz-1, mod_base));

                if (rva) {
                    addr = RVA2ADDR(rva, mod_base);
                    b_virt_det=TRUE;

                    dbgprintf("  Address [RVA]:0x%p [0x%08X]\n", addr, rva);
                } else dbgprintf("  Not loaded to memory!\n");
            } else {
                dbgprintf("  Outside sects!\n");
            }
        }
    } else goto err;

no_err:
    if (b_virt_det && flags_dsc[2].is_pres)
    {
        IDebugDataSpaces2 *DebugDataSpaces2;
        if (get_client()->QueryInterface(
            __uuidof(IDebugDataSpaces2), (void **)&DebugDataSpaces2)==S_OK)
        {
            MEMORY_BASIC_INFORMATION64 vinfo;
            if (DebugDataSpaces2->QueryVirtual(addr, &vinfo)==S_OK)
            {
                dbgprintf("Virtual memory info:\n");
                dbgprintf("  Base address: 0x%p\n", vinfo.BaseAddress);
                dbgprintf("  Alloc base:   0x%p\n", vinfo.AllocationBase);
                dbgprintf("  Alloc protect:0x%08X", vinfo.AllocationProtect);
                print_flags(
                    MEMINFOVALS_HT, NUM_MEMINFOVALS, vinfo.AllocationProtect, 32);
                dbgprintf("  Region size:  0x%p\n", vinfo.RegionSize);
                dbgprintf("  State:        0x%08X", vinfo.State);
                print_flags(MEMINFOVALS_HT, NUM_MEMINFOVALS, vinfo.State, 32); 
                dbgprintf("  Protect:      0x%08X", vinfo.Protect);
                print_flags(MEMINFOVALS_HT, NUM_MEMINFOVALS, vinfo.Protect, 32); 
                dbgprintf("  Type:         0x%08X", vinfo.Type);
                print_flags(MEMINFOVALS_HT, NUM_MEMINFOVALS, vinfo.Type, 32); 
            }
            DebugDataSpaces2->Release();
        }
    }
    ret=S_OK;

err:
    if (DebugSymbols) DebugSymbols->Release();
    if (DebugSymbols2) DebugSymbols2->Release();
    return ret;
}

/* dump_sects_chrt [-c] [mod_base] */
HRESULT CALLBACK
dump_sects_chrt(PDEBUG_CLIENT4 Client, PCSTR args)
{
    HRESULT ret=E_FAIL;
    set_client(Client);

    DWORD flags=0;
    flag_desc_t flags_dsc[] = {{'c', TRUE}};
    UINT n_flags = sizeof(flags_dsc)/sizeof(flags_dsc[0]);

    size_t rd_sz = read_flags(args, flags_dsc, n_flags);
    args += rd_sz;

    if (flags_dsc[0].is_pres) flags|=PROPSC_READ_CONF;

    char img_name[MAX_PATH+1];
    ULONG64 mod_base = get_mod_base(&args, NULL, img_name);
    if (!mod_base || strlen(args)) goto finish;

    info_dbgprintf("Base address of the module: 0x%p [%s]\n", mod_base, img_name);
    suggest_sects_chrt_name(mod_base, flags);

    ret=S_OK;
finish:
    return ret;
}

/* dump_serach family of commands */
HRESULT CALLBACK
dump_serach(PDEBUG_CLIENT4 Client, PCSTR args)
{
    HRESULT ret=E_FAIL;
    set_client(Client);

    if (is_cmd(args, "idt", 1, &args))
    {
        DWORD flags = SRCHIDT_NO_ORD;
        flag_desc_t flags_dsc[] =
            {{'x', FALSE}, {'s', TRUE}, {'r', TRUE}, {'a', TRUE}, {'l', TRUE}};

        rng_spec_t rng;
        UINT n_flags = sizeof(flags_dsc)/sizeof(flags_dsc[0]);

        rngspc_rc_t rc = get_range_spec(&args, flags_dsc, n_flags, &rng);
        if (rc==rngspc_err) goto finish;

        if (flags_dsc[0].is_pres) flags|=SRCHIDT_SILENT;

        ULONG64 rng_addr=NULL;
        if (rc==rngspc_ok && !rng.is_sect && !rng.rng.is_rva)
            rng_addr=rng.rng.addr;

        char img_name[MAX_PATH+1];
        ULONG64 mod_base = get_mod_base(&args, rng_addr, img_name);
        if (!mod_base || strlen(args)) goto finish;

        if (!(flags&SRCHIDT_SILENT))
            info_dbgprintf(
                "Base address of the module: 0x%p [%s]\n", mod_base, img_name);

        search_idt(mod_base, (rc==rngspc_not_prov ? NULL : &rng), flags);
    }

    ret=S_OK;
finish:
    return ret;
}

/* dump_conf [conf_file] */
HRESULT CALLBACK
dump_conf(PDEBUG_CLIENT4 Client, PCSTR args)
{
    PCSTR pc;

    set_client(Client);
    for (pc=args; isspace(*pc); pc++);

    if (*pc)
    {
        set_prop_file(pc);

        FILE *f = fopen(PROP_FILE, "r");
        if (!f) {
            warn_dbgprintf("Can not open config file: ");
        } else {
            info_dbgprintf("New config file: ");
            fclose(f);
        }
    } else {
        info_dbgprintf("Current config file: ");
    }

    dbgprintf("%s\n", PROP_FILE);
    return S_OK;
}

/* help info */
HRESULT CALLBACK
help(PDEBUG_CLIENT4 Client, PCSTR args)
{
    set_client(Client);

    dbgprintf(
"dumpext: PE files fix, dump & analysis\n\n"
"dump_imp_scan iat [-w] [[-s *|n]|[-a|-r addr -l len]] [mod_base]\n"
"    IAT imports scanning at specified memory range or of a given module with a\n"
"    base mod_base. This is the most generic method for import scanning.\n"
"    -s,r,a,l: Scanning range specification; that is a section number ('*' denotes\n"
"        all sections) or a memory range specified by an address or rva.\n"
"    -w: Write resolved imports to the config file.\n"
"dump_imp_scan idt [-w] [-a|-r addr [-l len]] [mod_base]\n"
"    IDT imports scanning at specified address of the IDT table or of a given module\n"
"    with a base mod_base. This command may be used only if IDT location is known\n"
"    and the IDT is not corrupted.\n"
"    -a,r,l: Specifies an address or rva of the IDT table with an optional length\n"
"        constraint.\n"
"    -w: Write resolved imports to the config file.\n\n"
"dump_pe [-s *|n] [mod_base]\n"
"    Dump a module with an address mod_base to a file.\n"
"    -s: Specifies section to extract into separate file. '*' denotes all sections.\n\n"
"dump_pe_info [header] [-m] [-h] [-d] [-s] [mod_base]\n"
"    Show PE details contained in the headers' part of a module with the address\n"
"    mod_base.\n"
"    -m: DOS header\n"
"    -h: PE headers (file and optional)\n"
"    -d: PE directories info\n"
"    -s: Sections table\n"
"dump_pe_info export|import|bimport|dimport|debug|lconf|rsrc|tls|reloc|except\n"
"             [-c|-C] [-x] [-v|-V] [-a|-r addr [-l len]] [mod_base]\n"
"    Show PE directory details at specified addr or of a given module with a base\n"
"    mod_base.\n"
"    -c,C: {rsrc} Show resource capacity details (-c); exclusively (-C).\n"
"    -x: {import} Use the imports spec. format of the config file in the output.\n"
"    -v,V: {except} Show verbose (-v) and even more verbose (-V) exception table\n"
"        details. All the provided informations are platform specific.\n"
"    -a,r: {all cases} Specifies an address or rva of the directory.\n"
"    -l: {import,bimport,dimport,reloc,except} An optional length constraint.\n\n"
"dump_offset_info [-v] {-a addr}|{-f ftpr [mod_base]}\n"
"    Show address or file pointer details\n"
"    -a: Address details\n"
"    -f: File pointer details\n"
"    -v: Show virtual memory details.\n\n"
"dump_sects_chrt [-c] [mod_base]\n"
"    Analyse PE headers to recognize sections names and characteristics. Print\n"
"    the result in a format ready to use in the configuration file. Useful for\n"
"    packers destroying mentioned data.\n"
"    -c: Read and take into account the configuration (PE headers, sections,\n"
"        directories)\n\n"
"dump_serach idt [-x] [[-s *|n]|[-a|-r addr -l len]] [mod_base]\n"
"    Search for and analyse the IDT table with IAT addresses matching the ones\n"
"    specified in the imports spec. in the config file. The command shall be used\n"
"    for searching destination location of the fixed imports with not modified\n"
"    IDT table.\n"
"    -s,r,a,l: Searching range specification; that is a section number ('*'\n"
"        denotes all sections) or a memory range specified by an address or rva.\n"
"    -x: Silent mode. In case of successful search the result is printed in a\n"
"        format used by the configuration file.\n\n"
"dump_conf [conf_file]\n"
"    Set configuration file to conf_file. If the file is not specified the current\n"
"    configuration file is displayed.\n\n"
"help\n"
"    Show this help.\n");

    return S_OK;
}
