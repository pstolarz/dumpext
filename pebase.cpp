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

#include <sys/types.h>
#include <sys/stat.h>

/* type of a PE pointers */
typedef enum _pe_ptrtpy_t
{
    pe_ptrtpy_raw=0,    /* pointer to raw data */
    pe_ptrtpy_rva       /* relative virtual address */
} pe_ptrtpy_t;


/* PE dirs names */
static struct
{
    const char *name_rva;   /* name of a dir (rva part) */
    const char *name_sz;    /* name of a dir (size part) */
} dir_names[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] =
{
    {PROP_DIRS_EXP_RVA, PROP_DIRS_EXP_SZ},
    {PROP_DIRS_IDT_RVA, PROP_DIRS_IDT_SZ},
    {PROP_DIRS_RSRC_RVA, PROP_DIRS_RSRC_SZ},
    {PROP_DIRS_EXPT_RVA, PROP_DIRS_EXPT_SZ},
    {PROP_DIRS_CERT_RVA, PROP_DIRS_CERT_SZ},
    {PROP_DIRS_RELOC_RVA, PROP_DIRS_RELOC_SZ},
    {PROP_DIRS_DBG_RVA, PROP_DIRS_DBG_SZ},
    {PROP_DIRS_ARCH_RVA, PROP_DIRS_ARCH_SZ},
    {PROP_DIRS_GPTR_RVA, PROP_DIRS_GPTR_SZ},
    {PROP_DIRS_TLS_RVA, PROP_DIRS_TLS_SZ},
    {PROP_DIRS_CFG_RVA, PROP_DIRS_CFG_SZ},
    {PROP_DIRS_BOUND_RVA, PROP_DIRS_BOUND_SZ},
    {PROP_DIRS_IAT_RVA, PROP_DIRS_IAT_SZ},
    {PROP_DIRS_DELAY_RVA, PROP_DIRS_DELAY_SZ},
    {PROP_DIRS_CLR_RVA, PROP_DIRS_CLR_SZ},
    {"Reserved.rva", "Reserved.size"}
};

/* section content bitmap flags */
#define SCONT_EXPORT        0x00000001U
#define SCONT_IMPORT        0x00000002U
#define SCONT_RSRC          0x00000004U
#define SCONT_EXCEPTION     0x00000008U
#define SCONT_SECURITY      0x00000010U
#define SCONT_RELOC         0x00000020U
#define SCONT_DEBUG         0x00000040U
#define SCONT_DEBUG_DTA     0x00000080U
#define SCONT_ARCH          0x00000100U
#define SCONT_TLS           0x00000200U
#define SCONT_TLS_DTA       0x00000400U
#define SCONT_LOAD_CFG      0x00000800U
#define SCONT_BND_IMPORT    0x00001000U
#define SCONT_DELAY_IMPORT  0x00002000U
#define SCONT_COM_DESC      0x00004000U
#define SCONT_CODE          0x00008000U
#define SCONT_DATA          0x00010000U
#define SCONT_COFF_SYMTAB   0x00020000U
#define SCONT_COFF_RELOC    0x00040000U
#define SCONT_COFF_LINE_NUM 0x00080000U

static struct
{
    const char *pc_name;    /* section name */
    DWORD cont;             /* max content */
    DWORD chrt;             /* typical characteristics */
} sects_pattrn[] =
{
    {".edata",
        SCONT_EXPORT,
        IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ
    },
    {".idata",
        SCONT_IMPORT,
        IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ
    },
    {".rsrc",
        SCONT_RSRC,
        IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ
    },
    {".tls",
        SCONT_TLS_DTA,
        IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE
    },
    {".reloc",
        SCONT_RELOC,
        IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_DISCARDABLE
    },
    {".debug",
        SCONT_DEBUG_DTA|SCONT_COFF_SYMTAB|SCONT_COFF_RELOC|SCONT_COFF_LINE_NUM,
        IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_DISCARDABLE
    },
    {".didat",
        SCONT_DELAY_IMPORT,
        IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ
    },
    {".pdata",
        SCONT_EXCEPTION,
        IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ
    },
    {".rdata",
        SCONT_EXPORT|SCONT_IMPORT|SCONT_EXCEPTION|SCONT_SECURITY|SCONT_RELOC|
            SCONT_DEBUG|SCONT_DEBUG_DTA|SCONT_ARCH|SCONT_TLS|SCONT_LOAD_CFG|
            SCONT_BND_IMPORT|SCONT_DELAY_IMPORT|SCONT_COM_DESC|SCONT_DATA|
            SCONT_COFF_SYMTAB|SCONT_COFF_RELOC|SCONT_COFF_LINE_NUM,
        IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ
    },
    {".text",
        SCONT_EXPORT|SCONT_IMPORT|SCONT_EXCEPTION|SCONT_SECURITY|SCONT_RELOC|
            SCONT_DEBUG|SCONT_DEBUG_DTA|SCONT_ARCH|SCONT_TLS|SCONT_LOAD_CFG|
            SCONT_BND_IMPORT|SCONT_DELAY_IMPORT|SCONT_COM_DESC|SCONT_CODE|
            SCONT_DATA|SCONT_COFF_SYMTAB|SCONT_COFF_RELOC|SCONT_COFF_LINE_NUM,
        IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ
    }
};

/* exported; see header for details */
BOOL read_pe_headers(ULONG64 mod_base, IMAGE_DOS_HEADER *p_dos_hdr,
    image_nt_headers_t *p_nt_hdrs, ULONG64 *p_sectab_addr, BOOL b_logs)
{
    ULONG cb;
    BOOL ret=FALSE;
    DWORD hdrs_off=0;

   /* read DOS header */
    if (!(read_memory(mod_base, p_dos_hdr, sizeof(*p_dos_hdr), &cb) &&
        cb==sizeof(*p_dos_hdr))) goto finish;

    if (p_dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) {
        if (b_logs) {
            err_dbgprintf("Invalid DOS header; magic: 0x%04X\n",
                (UINT)get_16uint_le(&p_dos_hdr->e_magic));
        }
        goto finish;
    }

    /* read PE signature, PE header & optional header */
    hdrs_off = get_32uint_le(&p_dos_hdr->e_lfanew);
    ULONG64 nt_hdrs_addr = mod_base + hdrs_off;

    if (!(read_memory(nt_hdrs_addr, &(p_nt_hdrs->hdr), sizeof(p_nt_hdrs->hdr), &cb)
        && cb==sizeof(p_nt_hdrs->hdr))) goto finish;

    if (get_Signature(p_nt_hdrs) != IMAGE_NT_SIGNATURE)
    {
        if (b_logs) {
            err_dbgprintf("Invalid PE header; signature 0x%08X\n",
                get_32uint_le(&get_Signature(p_nt_hdrs)));
        }
        goto finish;
    }

    DWORD opt_hdr_sz =
        get_16uint_le(&get_FileHeader(p_nt_hdrs).SizeOfOptionalHeader);

    hdrs_off += sizeof(get_Signature(p_nt_hdrs)) +
        sizeof(get_FileHeader(p_nt_hdrs)) + opt_hdr_sz;

    if (!opt_hdr_sz) {
        if (b_logs) err_dbgprintf("No optional header\n");
        goto finish;
    }

    /* check the opt header */
    WORD opt_magic = get_16uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.Magic);
    if (opt_magic==IMAGE_NT_OPTIONAL_HDR32_MAGIC) p_nt_hdrs->pe_tpy=pe_32bit;
    else
    if (opt_magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC)  p_nt_hdrs->pe_tpy=pe_64bit;
    else
    {
        if (b_logs)
            err_dbgprintf("Unsupported PE type: 0x%04X\n", (UINT)opt_magic);
        goto finish;
    }

    DWORD base_opt_hdr_len =
        (p_nt_hdrs->pe_tpy==pe_32bit ?
        ((UINT8*)&p_nt_hdrs->hdr.pe32.OptionalHeader.DataDirectory -
            (UINT8*)&p_nt_hdrs->hdr.pe32.OptionalHeader.Magic):
        ((UINT8*)&p_nt_hdrs->hdr.pe64.OptionalHeader.DataDirectory -
            (UINT8*)&p_nt_hdrs->hdr.pe64.OptionalHeader.Magic));

    if (base_opt_hdr_len >= opt_hdr_sz) {
        if (b_logs) err_dbgprintf("No NT specific optional header\n");
        goto finish;
    }

    if (p_sectab_addr) *p_sectab_addr = mod_base+hdrs_off;

    ret=TRUE;
finish:
    return ret;
}

/* exported; see header for details */
DWORD read_sectab(const image_nt_headers_t *p_nt_hdrs, ULONG64 sectab_addr,
    IMAGE_SECTION_HEADER *p_sectab, BOOL b_fix_empty_rng, BOOL b_logs)
{
    DWORD n_sects = get_16uint_le(&get_FileHeader(p_nt_hdrs).NumberOfSections);

    if (n_sects > MAX_SECTIONS) {
        err_dbgprintf("Number of sections in PE file exceeds %d\n", MAX_SECTIONS);
        n_sects=0;
    } else
    if (n_sects)
    {
        ULONG cb;
        DWORD sectab_len = sizeof(*p_sectab)*n_sects;
        if (!(read_memory(
            sectab_addr, p_sectab, sectab_len, &cb) && cb==sectab_len))
        {
            n_sects = 0;
        } else
        {
            if (b_fix_empty_rng) {
                for (DWORD i=0; i<n_sects; i++) {
                    DWORD sec_vsz = get_32uint_le(&p_sectab[i].Misc.VirtualSize);
                    DWORD sec_rva = get_32uint_le(&p_sectab[i].VirtualAddress);
                    DWORD sec_rsz = get_32uint_le(&p_sectab[i].SizeOfRawData);
                    DWORD sec_rptr = get_32uint_le(&p_sectab[i].PointerToRawData);

                    if (!sec_vsz || !sec_rva) {
                        set_32uint_le(&p_sectab[i].Misc.VirtualSize, 0);
                        set_32uint_le(&p_sectab[i].VirtualAddress, 0);
                    }
                    if (!sec_rsz || !sec_rptr) {
                        set_32uint_le(&p_sectab[i].SizeOfRawData, 0);
                        set_32uint_le(&p_sectab[i].PointerToRawData, 0);
                    }
                }
            }
        }
    }

    return n_sects;
}

/* exported; see header for details */
BOOL get_data_dir(const image_nt_headers_t *p_nt_hdrs,
    UINT dir_id, IMAGE_DATA_DIRECTORY **pp_dir_entry, BOOL b_logs)
{
    BOOL ret=FALSE;

    DWORD num_dir_ents =
        (p_nt_hdrs->pe_tpy==pe_32bit ?
        get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.NumberOfRvaAndSizes):
        get_32uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.NumberOfRvaAndSizes));

    if (num_dir_ents <= dir_id) {
        if (b_logs)
            err_dbgprintf("No PE dir entry for directory 0x%02X\n", dir_id);
        goto finish;
    }

    *pp_dir_entry =
        (IMAGE_DATA_DIRECTORY*)(p_nt_hdrs->pe_tpy==pe_32bit ?
        &p_nt_hdrs->hdr.pe32.OptionalHeader.DataDirectory[dir_id]:
        &p_nt_hdrs->hdr.pe64.OptionalHeader.DataDirectory[dir_id]);

    ret=TRUE;
finish:
    return ret;
}

/* exported; see header for details */
BOOL get_rva_info(const IMAGE_SECTION_HEADER *p_sectab, DWORD n_sects, DWORD rva,
    DWORD *p_sect_i, DWORD *p_n_raw_rem, DWORD *p_n_va_rem, DWORD *p_rptr)
{
    if (p_sect_i) *p_sect_i = 0;
    if (p_n_raw_rem) *p_n_raw_rem = 0;
    if (p_n_va_rem) *p_n_va_rem = 0;
    if (p_rptr) *p_rptr = 0;

    DWORD i;
    for (i=0; i<n_sects; i++)
    {
        DWORD sec_vsz = get_32uint_le(&p_sectab[i].Misc.VirtualSize);
        DWORD sec_rva = get_32uint_le(&p_sectab[i].VirtualAddress);

        if (sec_vsz && sec_rva<=rva && rva<sec_rva+sec_vsz)
        {
            if (p_sect_i) *p_sect_i = i;

            DWORD sec_rsz = get_32uint_le(&p_sectab[i].SizeOfRawData);
            DWORD sec_rptr = get_32uint_le(&p_sectab[i].PointerToRawData);
            DWORD rva_off = rva-sec_rva;

            if (p_n_va_rem) *p_n_va_rem = sec_vsz-rva_off;

            if (rva_off<sec_rsz) {
                if (p_rptr) *p_rptr = sec_rptr+rva_off;
                if (p_n_raw_rem) *p_n_raw_rem = sec_rsz-rva_off;
            }
            break;
        }
    }

    return i<n_sects;
}

/* exported; see header for details */
BOOL get_rptr_info(const IMAGE_SECTION_HEADER *p_sectab,
    DWORD n_sects, DWORD rptr, DWORD *p_sect_i, DWORD *p_n_raw_rem, DWORD *p_rva)
{
    if (p_sect_i) *p_sect_i = 0;
    if (p_n_raw_rem) *p_n_raw_rem = 0;
    if (p_rva) *p_rva = 0;

    DWORD i;
    for (i=0; i<n_sects; i++)
    {
        DWORD sec_rsz = get_32uint_le(&p_sectab[i].SizeOfRawData);
        DWORD sec_rptr = get_32uint_le(&p_sectab[i].PointerToRawData);

        if (sec_rsz && sec_rptr<=rptr && rptr<sec_rptr+sec_rsz)
        {
            if (p_sect_i) *p_sect_i = i;

            DWORD sec_vsz = get_32uint_le(&p_sectab[i].Misc.VirtualSize);
            DWORD sec_rva = get_32uint_le(&p_sectab[i].VirtualAddress);
            DWORD rptr_off = rptr-sec_rptr;

            if (p_n_raw_rem) *p_n_raw_rem = sec_rsz-rptr_off;
            if (p_rva && sec_vsz) *p_rva = sec_rva+rptr_off;
            break;
        }
    }

    return i<n_sects;
}

typedef enum _ownfo_tpy_t
{
    ownfo_info_cont=0,  /* containment info */
    ownfo_wrn_out,      /* outside sects/header */
    ownfo_wrn_sticks    /* partially contained */
} ownfo_tpy_t;

/* Get info string (written under 'pc_sect_info' buffer at least 100 bytes long)
   informing about owning section or header of the 'ptr' pointer (type of the
   pointer indicated by 'ptrtpy'). 'p_sectab' & 'n_sects' describes sections
   table. If 'p_info_tpy' is not NULL type of returned information is written.
   If sz>0 then additionally check inclusion in the owning section/header of a
   block 'sz' long (starting from 'ptr').
 */
static void get_owner_info(ULONG64 mod_base, const image_nt_headers_t *p_nt_hdrs,
    char *pc_sect_info, const IMAGE_SECTION_HEADER *p_sectab, DWORD n_sects,
    DWORD ptr, pe_ptrtpy_t ptrtpy, DWORD sz, ownfo_tpy_t *p_info_tpy)
{
    ownfo_tpy_t info_tpy = ownfo_info_cont;

    DWORD hdrs_sz = (p_nt_hdrs->pe_tpy==pe_32bit ?
        get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.SizeOfHeaders):
        get_32uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.SizeOfHeaders));

    char ptr_addr[32];
    if (ptrtpy==pe_ptrtpy_rva) {
        sprintf(ptr_addr, "addr: 0x%p, ", RVA2ADDR(ptr, mod_base));
    } else
        *ptr_addr=0;

    /* check belonging to the PE header;
       RVA and raw pointer have the same values inside header */
    if (0<=ptr && ptr<hdrs_sz)
    {
        if (ptr+sz>hdrs_sz) info_tpy=ownfo_wrn_sticks;
        if (pc_sect_info) {
            sprintf(pc_sect_info, "   ; %sheader%s", ptr_addr,
                (info_tpy==ownfo_wrn_sticks ?
                ", WARN: sticks out beyond header area!" : ""));
        }
    } else
    {
        /* check belonging to the sections */
        DWORD sect_i;
        DWORD n_rem;

        BOOL rc = (ptrtpy==pe_ptrtpy_rva ?
            get_rva_info(p_sectab, n_sects, ptr, &sect_i, NULL, &n_rem, NULL):
            get_rptr_info(p_sectab, n_sects, ptr, &sect_i, &n_rem, NULL));

        if (rc) {
            if (sz>n_rem) info_tpy=ownfo_wrn_sticks;
            if (pc_sect_info) {
                sprintf(pc_sect_info, "   ; %ssection %d%s", ptr_addr, sect_i+1,
                    (info_tpy==ownfo_wrn_sticks ?
                    ", WARN: sticks out beyond its section!" : ""));
            }
        } else {
            info_tpy=ownfo_wrn_out;
            if (pc_sect_info) sprintf(pc_sect_info,
                "   ; %sWARN: not contained in any section!", ptr_addr);
        }
    }

    if (p_info_tpy) *p_info_tpy=info_tpy;
}

/* Print DOS header details */
static void print_hdr_dos(const IMAGE_DOS_HEADER *p_dos_hdr)
{
    dbgprintf("[dos_header]\n");
    dbgprintf("e_magic = 0x%04X\n", (UINT)get_16uint_le(&p_dos_hdr->e_magic));
    dbgprintf("e_cblp = 0x%04X\n", (UINT)get_16uint_le(&p_dos_hdr->e_cblp));
    dbgprintf("e_cp = 0x%04X\n", (UINT)get_16uint_le(&p_dos_hdr->e_cp));
    dbgprintf("e_crlc = 0x%04X\n", (UINT)get_16uint_le(&p_dos_hdr->e_crlc));
    dbgprintf("e_cparhdr = 0x%04X\n", (UINT)get_16uint_le(&p_dos_hdr->e_cparhdr));
    dbgprintf("e_minalloc = 0x%04X\n", (UINT)get_16uint_le(&p_dos_hdr->e_minalloc));
    dbgprintf("e_maxalloc = 0x%04X\n", (UINT)get_16uint_le(&p_dos_hdr->e_maxalloc));
    dbgprintf("e_ss = 0x%04X\n", (UINT)get_16uint_le(&p_dos_hdr->e_ss));
    dbgprintf("e_sp = 0x%04X\n", (UINT)get_16uint_le(&p_dos_hdr->e_sp));
    dbgprintf("e_csum = 0x%04X\n", (UINT)get_16uint_le(&p_dos_hdr->e_csum));
    dbgprintf("e_ip = 0x%04X\n", (UINT)get_16uint_le(&p_dos_hdr->e_ip));
    dbgprintf("e_cs = 0x%04X\n", (UINT)get_16uint_le(&p_dos_hdr->e_cs));
    dbgprintf("e_lfarlc = 0x%04X\n", (UINT)get_16uint_le(&p_dos_hdr->e_lfarlc));
    dbgprintf("e_ovno = 0x%04X\n", (UINT)get_16uint_le(&p_dos_hdr->e_ovno));
    dbgprintf("e_oemid = 0x%04X\n", (UINT)get_16uint_le(&p_dos_hdr->e_oemid));
    dbgprintf("e_oeminfo = 0x%04X\n", (UINT)get_16uint_le(&p_dos_hdr->e_oeminfo));
    dbgprintf("e_lfanew = 0x%08X\n\n", get_32uint_le(&p_dos_hdr->e_lfanew));
}

/* print PE file header details */
static void print_hdr_file(ULONG64 mod_base, const image_nt_headers_t *p_nt_hdrs,
    const IMAGE_SECTION_HEADER *p_sectab, DWORD n_sects)
{
    const static str_num_t machine_ht[] =
    {
        {"unknown",0}, {"x86",0x014c}, {"mips r3000 BE",0x160},
        {"mips r3000 LE",0x162}, {"mips r4000 LE",0x0166},
        {"mips r10000 LE",0x0168}, {"mips wce v2 LE",0x0169}, {"alpha",0x0184},
        {"sh3 LE",0x01a2}, {"sh3 dsp",0x01a3}, {"sh3e LE",0x01a4},
        {"sh4 LE",0x01a6}, {"sh5",0x01a8}, {"arm LE",0x01c0}, {"thumb",0x01c2},
        {"arm v7",0x01c4}, {"am33",0x01d3}, {"ppc LE",0x01f0}, {"ppc fpu",0x01f1},
        {"ia64",0x0200}, {"mips 16",0x0266}, {"alpha64",0x0284},
        {"mips fpu",0x0366}, {"mips fpu 16",0x0466}, {"infineon",0x0520},
        {"cef",0x0CEF}, {"efi",0x0EBC}, {"x64",0x8664}, {"m32r LE",0x9041},
        {"cee",0xC0EE}
    };

    const IMAGE_FILE_HEADER *p_fh = &get_FileHeader(p_nt_hdrs);

    DWORD rptr;
    WORD chrt, machine;
    char sect_info[100];

    dbgprintf("[file_header]\n");
    dbgprintf("Machine = 0x%04X   ; %s\n",
        (UINT)(machine=get_16uint_le(&p_fh->Machine)),
        get_ht_str(machine_ht,
            sizeof(machine_ht)/sizeof(machine_ht[0]), (DWORD)machine, "???"));
    dbgprintf("NumberOfSections = 0x%04X\n",
        (UINT)get_16uint_le(&p_fh->NumberOfSections));
    dbgprintf("TimeDateStamp = 0x%08X\n", get_32uint_le(&p_fh->TimeDateStamp));

    DWORD n_syms = get_32uint_le(&p_fh->NumberOfSymbols);
    if (rptr = get_32uint_le(&p_fh->PointerToSymbolTable)) {
        get_owner_info(mod_base, p_nt_hdrs, sect_info, p_sectab, n_sects,
            rptr, pe_ptrtpy_raw, n_syms*sizeof(IMAGE_SYMBOL), NULL);
    } else *sect_info=0;
    dbgprintf("PointerToSymbolTable = 0x%08X%s\n", rptr, sect_info);

    dbgprintf("NumberOfSymbols = 0x%08X\n", n_syms);
    dbgprintf("SizeOfOptionalHeader = 0x%04X\n",
        (UINT)get_16uint_le(&p_fh->SizeOfOptionalHeader));

    dbgprintf("Characteristics = 0x%04X",
        (UINT)(chrt = get_16uint_le(&p_fh->Characteristics)));
    print_flags(FLCHRVALS_HT, NUM_FLCHRVALS, (DWORD)chrt, 16);

    dbgprintf("\n");
}

/* Print PE optional header details */
static void print_hdr_opt(ULONG64 mod_base, const image_nt_headers_t *p_nt_hdrs,
    const IMAGE_SECTION_HEADER *p_sectab, DWORD n_sects)
{
    const static str_num_t subsys_ht[] =
    {
        {"unknown",0}, {"native",1}, {"win gui",2}, {"win cui",3}, {"os2 cui",5},
        {"posix cui",7}, {"win native",8}, {"win ce gui",9}, {"efi app",10},
        {"efi boot service driver",11}, {"efi runtime driver",12}, {"efi rom",13},
        {"xbox",14}, {"win boot app",16}
    };

    DWORD rva;
    WORD chrt, subsys;
    char sect_info[100];

    dbgprintf("[%s]\n", PROP_SECT_OPTH);
    if (p_nt_hdrs->pe_tpy==pe_32bit)
    {
        dbgprintf("Magic = 0x%04X   ; PE32\n",
            (UINT)get_16uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.Magic));
        dbgprintf("MajorLinkerVersion = 0x%02X\n",
            (UINT)p_nt_hdrs->hdr.pe32.OptionalHeader.MajorLinkerVersion);
        dbgprintf("MinorLinkerVersion = 0x%02X\n",
            (UINT)p_nt_hdrs->hdr.pe32.OptionalHeader.MinorLinkerVersion);
        dbgprintf("SizeOfCode = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.SizeOfCode));
        dbgprintf("SizeOfInitializedData = 0x%08X\n",
            get_32uint_le(
                &p_nt_hdrs->hdr.pe32.OptionalHeader.SizeOfInitializedData));
        dbgprintf("SizeOfUninitializedData = 0x%08X\n",
            get_32uint_le(
                &p_nt_hdrs->hdr.pe32.OptionalHeader.SizeOfUninitializedData));

        if (rva = get_32uint_le(
            &p_nt_hdrs->hdr.pe32.OptionalHeader.AddressOfEntryPoint))
        {
            get_owner_info(mod_base, p_nt_hdrs, sect_info, p_sectab, n_sects,
                rva, pe_ptrtpy_rva, 0, NULL);
        } else
            *sect_info=0;
        dbgprintf("%s = 0x%08X%s\n", PROP_OPTH_ENTRY_POINT, rva, sect_info);

        if (rva = get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.BaseOfCode))
        {
            get_owner_info(mod_base, p_nt_hdrs, sect_info, p_sectab, n_sects,
                rva, pe_ptrtpy_rva, 0, NULL);
        } else
            *sect_info=0;
        dbgprintf("%s = 0x%08X%s\n", PROP_OPTH_BASE_CODE, rva, sect_info);

        if (rva = get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.BaseOfData))
        {
            get_owner_info(mod_base, p_nt_hdrs, sect_info, p_sectab, n_sects,
                rva, pe_ptrtpy_rva, 0, NULL);
        } else
            *sect_info=0;
        dbgprintf("%s = 0x%08X%s\n", PROP_OPTH_BASE_DATA, rva, sect_info);

        dbgprintf("ImageBase = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.ImageBase));
        dbgprintf("SectionAlignment = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.SectionAlignment));
        dbgprintf("FileAlignment = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.FileAlignment));
        dbgprintf("MajorOperatingSystemVersion = 0x%04X\n",
            (UINT)get_16uint_le(
                &p_nt_hdrs->hdr.pe32.OptionalHeader.MajorOperatingSystemVersion));
        dbgprintf("MinorOperatingSystemVersion = 0x%04X\n",
            (UINT)get_16uint_le(
                &p_nt_hdrs->hdr.pe32.OptionalHeader.MinorOperatingSystemVersion));
        dbgprintf("MajorImageVersion = 0x%04X\n",
            (UINT)get_16uint_le(
                &p_nt_hdrs->hdr.pe32.OptionalHeader.MajorImageVersion));
        dbgprintf("MinorImageVersion = 0x%04X\n",
            (UINT)get_16uint_le(
                &p_nt_hdrs->hdr.pe32.OptionalHeader.MinorImageVersion));
        dbgprintf("MajorSubsystemVersion = 0x%04X\n",
            (UINT)get_16uint_le(
                &p_nt_hdrs->hdr.pe32.OptionalHeader.MajorSubsystemVersion));
        dbgprintf("MinorSubsystemVersion = 0x%04X\n",
            (UINT)get_16uint_le(
                &p_nt_hdrs->hdr.pe32.OptionalHeader.MinorSubsystemVersion));
        dbgprintf("Win32VersionValue = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.Win32VersionValue));
        dbgprintf("SizeOfImage = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.SizeOfImage));
        dbgprintf("SizeOfHeaders = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.SizeOfHeaders));
        dbgprintf("CheckSum = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.CheckSum));
        dbgprintf("Subsystem = 0x%04X   ; %s\n",
            (UINT)(subsys=get_16uint_le(
                &p_nt_hdrs->hdr.pe32.OptionalHeader.Subsystem)),
            get_ht_str(subsys_ht,
                sizeof(subsys_ht)/sizeof(subsys_ht[0]), (DWORD)subsys, "???"));

        dbgprintf("DllCharacteristics = 0x%04X",
            (UINT)(chrt=get_16uint_le(
                &p_nt_hdrs->hdr.pe32.OptionalHeader.DllCharacteristics)));
        print_flags(DLLCHRVALS_HT, NUM_DLLCHRVALS, (DWORD)chrt, 16);

        dbgprintf("SizeOfStackReserve = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.SizeOfStackReserve));
        dbgprintf("SizeOfStackCommit = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.SizeOfStackCommit));
        dbgprintf("SizeOfHeapReserve = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.SizeOfHeapReserve));
        dbgprintf("SizeOfHeapCommit = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.SizeOfHeapCommit));
        dbgprintf("LoaderFlags = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.LoaderFlags));
        dbgprintf("NumberOfRvaAndSizes = 0x%08X\n\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.NumberOfRvaAndSizes));
    } else
    {
        dbgprintf("Magic = 0x%04X   ; PE32+\n",
            (UINT)get_16uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.Magic));
        dbgprintf("MajorLinkerVersion = 0x%02X\n",
            (UINT)p_nt_hdrs->hdr.pe64.OptionalHeader.MajorLinkerVersion);
        dbgprintf("MinorLinkerVersion = 0x%02X\n",
            (UINT)p_nt_hdrs->hdr.pe64.OptionalHeader.MinorLinkerVersion);
        dbgprintf("SizeOfCode = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.SizeOfCode));
        dbgprintf("SizeOfInitializedData = 0x%08X\n",
            get_32uint_le(
                &p_nt_hdrs->hdr.pe64.OptionalHeader.SizeOfInitializedData));
        dbgprintf("SizeOfUninitializedData = 0x%08X\n",
            get_32uint_le(
                &p_nt_hdrs->hdr.pe64.OptionalHeader.SizeOfUninitializedData));

        if (rva = get_32uint_le(
            &p_nt_hdrs->hdr.pe64.OptionalHeader.AddressOfEntryPoint))
        {
            get_owner_info(mod_base, p_nt_hdrs, sect_info, p_sectab, n_sects,
                rva, pe_ptrtpy_rva, 0, NULL);
        } else
            *sect_info=0;
        dbgprintf("%s = 0x%08X%s\n", PROP_OPTH_ENTRY_POINT, rva, sect_info);

        if (rva = get_32uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.BaseOfCode))
        {
            get_owner_info(mod_base, p_nt_hdrs, sect_info, p_sectab, n_sects,
                rva, pe_ptrtpy_rva, 0, NULL);
        } else
            *sect_info=0;
        dbgprintf("%s = 0x%08X%s\n", PROP_OPTH_BASE_CODE, rva, sect_info);

        dbgprintf("ImageBase = 0x%016I64X\n",
            get_64uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.ImageBase));
        dbgprintf("SectionAlignment = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.SectionAlignment));
        dbgprintf("FileAlignment = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.FileAlignment));
        dbgprintf("MajorOperatingSystemVersion = 0x%04X\n",
            (UINT)get_16uint_le(
                &p_nt_hdrs->hdr.pe64.OptionalHeader.MajorOperatingSystemVersion));
        dbgprintf("MinorOperatingSystemVersion = 0x%04X\n",
            (UINT)get_16uint_le(
                &p_nt_hdrs->hdr.pe64.OptionalHeader.MinorOperatingSystemVersion));
        dbgprintf("MajorImageVersion = 0x%04X\n",
            (UINT)get_16uint_le(
                &p_nt_hdrs->hdr.pe64.OptionalHeader.MajorImageVersion));
        dbgprintf("MinorImageVersion = 0x%04X\n",
            (UINT)get_16uint_le(
                &p_nt_hdrs->hdr.pe64.OptionalHeader.MinorImageVersion));
        dbgprintf("MajorSubsystemVersion = 0x%04X\n",
            (UINT)get_16uint_le(
                &p_nt_hdrs->hdr.pe64.OptionalHeader.MajorSubsystemVersion));
        dbgprintf("MinorSubsystemVersion = 0x%04X\n",
            (UINT)get_16uint_le(
                &p_nt_hdrs->hdr.pe64.OptionalHeader.MinorSubsystemVersion));
        dbgprintf("Win32VersionValue = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.Win32VersionValue));
        dbgprintf("SizeOfImage = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.SizeOfImage));
        dbgprintf("SizeOfHeaders = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.SizeOfHeaders));
        dbgprintf("CheckSum = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.CheckSum));
        dbgprintf("Subsystem = 0x%04X   ; %s\n",
            (UINT)(subsys=get_16uint_le(
                &p_nt_hdrs->hdr.pe64.OptionalHeader.Subsystem)),
            get_ht_str(subsys_ht,
                sizeof(subsys_ht)/sizeof(subsys_ht[0]), (DWORD)subsys, "???"));

        dbgprintf("DllCharacteristics = 0x%04X",
            (UINT)(chrt=get_16uint_le(
                &p_nt_hdrs->hdr.pe64.OptionalHeader.DllCharacteristics)));
        print_flags(DLLCHRVALS_HT, NUM_DLLCHRVALS, (DWORD)chrt, 16);

        dbgprintf("SizeOfStackReserve = 0x%016I64X\n",
            get_64uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.SizeOfStackReserve));
        dbgprintf("SizeOfStackCommit = 0x%016I64X\n",
            get_64uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.SizeOfStackCommit));
        dbgprintf("SizeOfHeapReserve = 0x%016I64X\n",
            get_64uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.SizeOfHeapReserve));
        dbgprintf("SizeOfHeapCommit = 0x%016I64X\n",
            get_64uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.SizeOfHeapCommit));
        dbgprintf("LoaderFlags = 0x%08X\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.LoaderFlags));
        dbgprintf("NumberOfRvaAndSizes = 0x%08X\n\n",
            get_32uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.NumberOfRvaAndSizes));
    }
}

typedef enum _dirfld_t
{
    dirfld_rva=0,
    dirfld_size
} dirfld_t;

/* Get PE's directory's field name and write it to the buffer 'pc_out_name' min.
   32 bytes long.
 */
static void get_dir_fld_name(UINT dir_id, dirfld_t dirfld, char *pc_out_name)
{
    if (dirfld==dirfld_rva)
    {
        if (dir_id<IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
            sprintf(pc_out_name, "%s", dir_names[dir_id].name_rva);
        } else {
            sprintf(pc_out_name, "%d.rva", dir_id+1);
        }
    } else
    {
        if (dir_id<IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
            sprintf(pc_out_name, "%s", dir_names[dir_id].name_sz);
        } else {
            sprintf(pc_out_name, "%d.size", dir_id+1);
        }
    }
}

/* Print PE directories details */
static void print_pe_dirs(ULONG64 mod_base, const image_nt_headers_t *p_nt_hdrs,
    const IMAGE_SECTION_HEADER *p_sectab, DWORD n_sects)
{
    DWORD num_dir_ents =
        (p_nt_hdrs->pe_tpy==pe_32bit ?
        get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.NumberOfRvaAndSizes):
        get_32uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.NumberOfRvaAndSizes));

    dbgprintf("[%s]\n", PROP_SECT_DIRS);

    for (DWORD i=0; i<num_dir_ents; i++)
    {
        const IMAGE_DATA_DIRECTORY *p_dir_ent =
            (p_nt_hdrs->pe_tpy==pe_32bit ?
            &p_nt_hdrs->hdr.pe32.OptionalHeader.DataDirectory[i]:
            &p_nt_hdrs->hdr.pe64.OptionalHeader.DataDirectory[i]);

        DWORD rva = get_32uint_le(&p_dir_ent->VirtualAddress);
        DWORD sz = get_32uint_le(&p_dir_ent->Size);

        char sect_info[100];
        *sect_info = 0;

        if (rva) {
            if (i==IMAGE_DIRECTORY_ENTRY_SECURITY)
            {
                ownfo_tpy_t ownfo_tpy;
                get_owner_info(mod_base, p_nt_hdrs, sect_info,
                    p_sectab, n_sects, rva, pe_ptrtpy_raw, sz, &ownfo_tpy);

                if (ownfo_tpy!=ownfo_info_cont)
                {
                    if (ownfo_tpy==ownfo_wrn_out) {
                        strcpy(sect_info, "   ; file ptr, "
                            "WARN: not contained in any section!");
                    } else {
                        strcpy(sect_info, "   ; file ptr, "
                            "WARN: sticks out beyond its section size!");
                    }
                }
            } else {
                get_owner_info(mod_base, p_nt_hdrs, sect_info,
                    p_sectab, n_sects, rva, pe_ptrtpy_rva, sz, NULL);
            }
        }

        char prm_name[32];

        get_dir_fld_name(i, dirfld_rva, prm_name);
        dbgprintf("%s = 0x%08X%s\n", prm_name, rva, sect_info);

        get_dir_fld_name(i, dirfld_size, prm_name);
        dbgprintf("%s = 0x%08X\n", prm_name, sz);
    }

    dbgprintf("\n");
}

/* Print sections table details */
static void print_sectab(ULONG64 mod_base, const image_nt_headers_t *p_nt_hdrs,
    const IMAGE_SECTION_HEADER *p_sectab, DWORD n_sects)
{
    dbgprintf("[%s]\n", PROP_SECT_SECTS);

    for (DWORD i=0; i<n_sects; i++)
    {
        DWORD chrt=0, rptr, rva;
        char sect_info[100];

        char sec_name[IMAGE_SIZEOF_SHORT_NAME+1];
        strncpy(sec_name, (char*)&p_sectab[i].Name[0], sizeof(sec_name)-1);
        sec_name[sizeof(sec_name)-1] = 0;
        dbgprintf("%d.%s = %s\n", i+1, PROP_SECTS_NAME, sec_name);

        dbgprintf("%d.%s = 0x%08X\n", i+1,
            PROP_SECTS_VSZ, get_32uint_le(&p_sectab[i].Misc.VirtualSize));

        rva = get_32uint_le(&p_sectab[i].VirtualAddress);
        dbgprintf("%d.VirtualAddress = 0x%08X", i+1, rva);
        if (rva) dbgprintf("   ; addr: 0x%p\n", RVA2ADDR(rva, mod_base));
        else dbgprintf("\n");

        dbgprintf("%d.%s = 0x%08X\n",
            i+1, PROP_SECTS_RSZ, get_32uint_le(&p_sectab[i].SizeOfRawData));
        dbgprintf("%d.PointerToRawData = 0x%08X\n",
            i+1, get_32uint_le(&p_sectab[i].PointerToRawData));

        DWORD n_relocs = get_16uint_le(&p_sectab[i].NumberOfRelocations);
        if (rptr = get_32uint_le(&p_sectab[i].PointerToRelocations))
        {
            get_owner_info(mod_base, p_nt_hdrs, sect_info, p_sectab, n_sects,
                rptr, pe_ptrtpy_raw, n_relocs*sizeof(IMAGE_RELOCATION), NULL);
        } else *sect_info=0;
        dbgprintf("%d.PointerToRelocations = 0x%08X%s\n", i+1, rptr, sect_info);

        DWORD n_lines = get_16uint_le(&p_sectab[i].NumberOfLinenumbers);
        if (rptr = get_32uint_le(&p_sectab[i].PointerToLinenumbers)) {
            get_owner_info(mod_base, p_nt_hdrs, sect_info, p_sectab, n_sects,
                rptr, pe_ptrtpy_raw, n_lines*sizeof(IMAGE_LINENUMBER), NULL);
        } else *sect_info=0;
        dbgprintf("%d.PointerToLinenumbers = 0x%08X%s\n", i+1, rptr, sect_info);

        dbgprintf("%d.NumberOfRelocations = 0x%04X\n", i+1, n_relocs);
        dbgprintf("%d.NumberOfLinenumbers = 0x%04X\n", i+1, n_lines);

        dbgprintf("%d.%s = 0x%08X", i+1, PROP_SECTS_CHARACTER,
            (chrt = get_32uint_le(&p_sectab[i].Characteristics)));
        print_flags(SECCHRVALS_HT, NUM_SECCHRVALS, chrt, 32);
    }
    dbgprintf("\n");
}

/* exported; see header for details */
void print_pe_details(ULONG64 mod_base, DWORD flags)
{
    IMAGE_DOS_HEADER dos_hdr;
    image_nt_headers_t nt_hdrs;
    ULONG64 sectab_addr;

    if (!read_pe_headers(mod_base, &dos_hdr, &nt_hdrs, &sectab_addr, TRUE))
        goto finish;

    IMAGE_SECTION_HEADER sectab[MAX_SECTIONS];
    DWORD n_sects = read_sectab(&nt_hdrs, sectab_addr, sectab, FALSE, TRUE);

    if (flags&PRNTPE_DOS_HEADER) print_hdr_dos(&dos_hdr);
    if (flags&PRNTPE_PE_HEADERS) {
        print_hdr_file(mod_base, &nt_hdrs, sectab, n_sects);
        print_hdr_opt(mod_base, &nt_hdrs, sectab, n_sects);
    }

    if (flags&PRNTPE_DIRS) print_pe_dirs(mod_base, &nt_hdrs, sectab, n_sects);

    if (flags&PRNTPE_SECTS) print_sectab(mod_base, &nt_hdrs, sectab, n_sects);

finish:
    return;
}

/* exported; see header for details */
BOOL init_prnt_dir_hndl(prnt_dir_hndl_t *p_hndl,
    ULONG64 mod_base, UINT dir_id, const rng_spec_t *p_rng)
{
    BOOL ret=FALSE;

    memset(p_hndl, 0, sizeof(*p_hndl));

    p_hndl->mod_base = mod_base;

    /* read PE header and the directory */
    ULONG64 sectab_addr;
    IMAGE_DOS_HEADER dos_hdr;
    if (!read_pe_headers(
        mod_base, &dos_hdr, &p_hndl->nt_hdrs, &sectab_addr, TRUE)) goto finish;

    p_hndl->n_sects =
        read_sectab(&p_hndl->nt_hdrs, sectab_addr, p_hndl->sectab, TRUE, TRUE);

    p_hndl->dir_id = dir_id;

    if (!p_rng)
    {
        IMAGE_DATA_DIRECTORY *p_dd;
        if (!get_data_dir(&p_hndl->nt_hdrs, dir_id, &p_dd, FALSE)) {
            info_dbgprintf("No data directory no. %d in the module\n", dir_id);
            goto finish;
        }

        p_hndl->dir_addr =
            RVA2ADDR(get_32uint_le(&p_dd->VirtualAddress), mod_base);
        p_hndl->dir_sz = get_32uint_le(&p_dd->Size);
    } else
    {
        if (p_rng->is_sect) goto finish;

        if (p_rng->rng.is_rva) {
            p_hndl->dir_addr = RVA2ADDR(p_rng->rng.rva, mod_base);
        } else {
            p_hndl->dir_addr = p_rng->rng.addr;
        }
        if (!p_hndl->dir_addr || !p_rng->rng.len) goto finish;

        p_hndl->dir_sz = 0;
    }

    ret=TRUE;
finish:
    return ret;
}

/* print_lconf() support routine */
static void print_seh_hndlrs(
    UINT64 seh_hndlrs_addr, UINT64 n_seh_hndlrs, UINT64 mod_base)
{
    ULONG cb;
    DWORD hndlr_rva;

    if (n_seh_hndlrs) dbgprintf(" SEH handlers:\n");
    for (;n_seh_hndlrs; n_seh_hndlrs--, seh_hndlrs_addr+=sizeof(hndlr_rva))
    {
        if (!(read_memory(seh_hndlrs_addr, &hndlr_rva, sizeof(hndlr_rva), &cb)
            && cb==sizeof(hndlr_rva))) break;

        dbgprintf("  0x%p[0x%08X]\n", RVA2ADDR(hndlr_rva, mod_base), hndlr_rva);
    }
}

/* exported; see header for details */
void print_lconf(ULONG64 mod_base, const rng_spec_t *p_rng)
{
    prnt_dir_hndl_t hndl;
    if (!init_prnt_dir_hndl(
        &hndl, mod_base, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, p_rng)) goto finish;

    /* print header */
    if (!hndl.dir_addr || (!p_rng && !hndl.dir_sz)) {
        info_dbgprintf("No load config descr. in this module!\n");
        goto finish;
    } else
    if (!p_rng && hndl.dir_sz!=0x40) {
        info_dbgprintf(
            "Unrecognised load config descr. with size 0x04X\n", hndl.dir_sz);
        goto finish;
    } else {
       info_dbgprintf("Load config descr. at: 0x%p\n", hndl.dir_addr);
    }

    info_dbgprintf("RVA provided in []\n\n");

    ULONG cb;
    ULONG64 addr, n_seh_hndlrs;

    if (hndl.nt_hdrs.pe_tpy==pe_32bit)
    {
        DWORD sec_cookie;

        /* 32-bit load conf */
        IMAGE_LOAD_CONFIG_DIRECTORY32 lconf;
        if (!(read_memory(hndl.dir_addr, &lconf, sizeof(lconf), &cb) &&
            cb==sizeof(lconf))) goto finish;

        dbgprintf("Size:                    0x%08X\n",
            get_32uint_le(&lconf.Size));
        dbgprintf("Timestamp:               0x%08X\n",
            get_32uint_le(&lconf.TimeDateStamp));
        dbgprintf("Major version:           0x%04X\n",
            get_16uint_le(&lconf.MajorVersion));
        dbgprintf("Minor version:           0x%04X\n",
            get_16uint_le(&lconf.MinorVersion));
        dbgprintf("Glob. flags clear:       0x%08X\n",
            get_32uint_le(&lconf.GlobalFlagsClear));
        dbgprintf("Glob. flags set:         0x%08X\n",
            get_32uint_le(&lconf.GlobalFlagsSet));
        dbgprintf("Crit-sect. def. timeout: 0x%08X\n",
            get_32uint_le(&lconf.CriticalSectionDefaultTimeout));
        dbgprintf("De-comm free blck thrsh: 0x%08X\n",
            get_32uint_le(&lconf.DeCommitFreeBlockThreshold));
        dbgprintf("De-comm total free thrsh:0x%08X\n",
            get_32uint_le(&lconf.DeCommitTotalFreeThreshold));
        addr = DEBUG_EXTEND64(get_32uint_le(&lconf.LockPrefixTable));
        dbgprintf("LOCK prefs table at:     0x%p[0x%08X]\n",
            addr, ADDR2RVA(addr, mod_base));
        dbgprintf("Max allocation size:     0x%08X\n",
            get_32uint_le(&lconf.MaximumAllocationSize));
        dbgprintf("Virtual memory threshold:0x%08X\n",
            get_32uint_le(&lconf.VirtualMemoryThreshold));
        dbgprintf("Process heap flags:      0x%08X\n",
            get_32uint_le(&lconf.ProcessHeapFlags));
        dbgprintf("Process affinity mask:   0x%08X\n",
            get_32uint_le(&lconf.ProcessAffinityMask));
        dbgprintf("CSD version:             0x%04X\n",
            get_16uint_le(&lconf.CSDVersion));
        dbgprintf("Reserved:                0x%04X\n",
            get_16uint_le(&lconf.Reserved1));
        addr = DEBUG_EXTEND64(get_32uint_le(&lconf.EditList));
        dbgprintf("Edit list at:            0x%p[0x%08X]\n",
            addr, ADDR2RVA(addr, mod_base));

        addr = DEBUG_EXTEND64(get_32uint_le(&lconf.SecurityCookie));
        dbgprintf("Security cookie at:      0x%p[0x%08X]",
            addr, ADDR2RVA(addr, mod_base));
        if (addr && read_memory(addr, &sec_cookie, sizeof(sec_cookie), &cb) &&
            cb==sizeof(sec_cookie))
        {
            dbgprintf(" -> 0x%08X\n", get_32uint_le(&sec_cookie));
        } else
            dbgprintf("\n");

        addr = DEBUG_EXTEND64(get_32uint_le(&lconf.SEHandlerTable));
        dbgprintf("SEH handlers table at:   0x%p[0x%08X]\n",
            addr, ADDR2RVA(addr, mod_base));
        n_seh_hndlrs = (ULONG64)get_32uint_le(&lconf.SEHandlerCount);
        dbgprintf("SEH handlers count:      0x%08X\n", (UINT)n_seh_hndlrs);
        print_seh_hndlrs(addr, n_seh_hndlrs, mod_base);
    } else
    {
        ULONG64 sec_cookie;

        /* 64-bit load conf */
        IMAGE_LOAD_CONFIG_DIRECTORY64 lconf;
        if (!(read_memory(hndl.dir_addr, &lconf, sizeof(lconf), &cb) &&
            cb==sizeof(lconf))) goto finish;

        dbgprintf("Size:                    0x%08X\n",
            get_32uint_le(&lconf.Size));
        dbgprintf("Timestamp:               0x%08X\n",
            get_32uint_le(&lconf.TimeDateStamp));
        dbgprintf("Major version:           0x%04X\n",
            get_16uint_le(&lconf.MajorVersion));
        dbgprintf("Minor version:           0x%04X\n",
            get_16uint_le(&lconf.MinorVersion));
        dbgprintf("Glob. flags clear:       0x%08X\n",
            get_32uint_le(&lconf.GlobalFlagsClear));
        dbgprintf("Glob. flags set:         0x%08X\n",
            get_32uint_le(&lconf.GlobalFlagsSet));
        dbgprintf("Crit-sect. def. timeout: 0x%08X\n",
            get_32uint_le(&lconf.CriticalSectionDefaultTimeout));
        dbgprintf("De-comm free blck thrsh: 0x%016I64X\n",
            get_64uint_le(&lconf.DeCommitFreeBlockThreshold));
        dbgprintf("De-comm total free thrsh:0x%016I64X\n",
            get_64uint_le(&lconf.DeCommitTotalFreeThreshold));
        addr = get_64uint_le(&lconf.LockPrefixTable);
        dbgprintf("LOCK prefs table at:     0x%p[0x%08X]\n",
            addr, ADDR2RVA(addr, mod_base));
        dbgprintf("Max allocation size:     0x%016I64X\n",
            get_64uint_le(&lconf.MaximumAllocationSize));
        dbgprintf("Virtual memory threshold:0x%016I64X\n",
            get_64uint_le(&lconf.VirtualMemoryThreshold));
        dbgprintf("Process affinity mask:   0x%016I64X\n",
            get_64uint_le(&lconf.ProcessAffinityMask));
        dbgprintf("Process heap flags:      0x%08X\n",
            get_32uint_le(&lconf.ProcessHeapFlags));
        dbgprintf("CSD version:             0x%04X\n",
            get_16uint_le(&lconf.CSDVersion));
        dbgprintf("Reserved:                0x%04X\n",
            get_16uint_le(&lconf.Reserved1));
        addr = get_64uint_le(&lconf.EditList);
        dbgprintf("Edit list at:            0x%p[0x%08X]\n",
            addr, ADDR2RVA(addr, mod_base));

        addr = get_64uint_le(&lconf.SecurityCookie);
        dbgprintf("Security cookie at:      0x%p[0x%08X]",
            addr, ADDR2RVA(addr, mod_base));
        if (addr && read_memory(addr, &sec_cookie, sizeof(sec_cookie), &cb) &&
            cb==sizeof(sec_cookie))
        {
            dbgprintf(" -> 0x%016I64X\n", get_64uint_le(&sec_cookie));
        } else
            dbgprintf("\n");

        addr = get_64uint_le(&lconf.SEHandlerTable);
        dbgprintf("SEH handlers table at:   0x%p[0x%08X]\n",
            addr, ADDR2RVA(addr, mod_base));
        n_seh_hndlrs = get_64uint_le(&lconf.SEHandlerCount);
        dbgprintf("SEH handlers count:      0x%016I64X\n",
            get_64uint_le(&lconf.SEHandlerCount));
        print_seh_hndlrs(addr, n_seh_hndlrs, mod_base);
    }

finish:
    return;
}

/* exported; see header for details */
void print_tls(ULONG64 mod_base, const rng_spec_t *p_rng)
{
    prnt_dir_hndl_t hndl;
    if (!init_prnt_dir_hndl(&hndl, mod_base, IMAGE_DIRECTORY_ENTRY_TLS, p_rng))
        goto finish;

    /* print header */
    if (!hndl.dir_addr || (!p_rng && !hndl.dir_sz)) {
        info_dbgprintf("No TLS descr. in this module!\n");
        goto finish;
    } else
        info_dbgprintf("TLS descr. at: 0x%p\n", hndl.dir_addr);

    info_dbgprintf("RVA provided in []\n\n");

    ULONG cb;
    ULONG64 start_addr;
    ULONG64 end_addr;
    ULONG64 tls_i_addr;
    ULONG64 callbacks_addr;
    DWORD zero_fill_sz;
    DWORD chrcts;

    if (hndl.nt_hdrs.pe_tpy==pe_32bit)
    {
        /* 32-bit TLS */
        IMAGE_TLS_DIRECTORY32 tls;
        if (!(read_memory(hndl.dir_addr, &tls, sizeof(tls), &cb) &&
            cb==sizeof(tls))) goto finish;

        start_addr = DEBUG_EXTEND64(get_32uint_le(&tls.StartAddressOfRawData));
        end_addr = DEBUG_EXTEND64(get_32uint_le(&tls.EndAddressOfRawData));
        tls_i_addr = DEBUG_EXTEND64(get_32uint_le(&tls.AddressOfIndex));
        callbacks_addr = DEBUG_EXTEND64(get_32uint_le(&tls.AddressOfCallBacks));
        zero_fill_sz = get_32uint_le(&tls.SizeOfZeroFill);
        chrcts = get_32uint_le(&tls.Characteristics);
    } else
    {
        /* 64-bit TLS */
        IMAGE_TLS_DIRECTORY64 tls;
        if (!(read_memory(hndl.dir_addr, &tls, sizeof(tls), &cb) &&
            cb==sizeof(tls))) goto finish;

        start_addr = get_64uint_le(&tls.StartAddressOfRawData);
        end_addr = get_64uint_le(&tls.EndAddressOfRawData);
        tls_i_addr = get_64uint_le(&tls.AddressOfIndex);
        callbacks_addr = get_64uint_le(&tls.AddressOfCallBacks);
        zero_fill_sz = get_32uint_le(&tls.SizeOfZeroFill);
        chrcts = get_32uint_le(&tls.Characteristics);
    }

    dbgprintf("Raw data starts at: 0x%p[0x%08X]\n",
        start_addr, ADDR2RVA(start_addr, mod_base));
    dbgprintf("Raw data ends at:   0x%p[0x%08X]   ; total data length: 0x%04X\n",
        end_addr, ADDR2RVA(end_addr, mod_base),
        (DWORD)((end_addr-start_addr)+zero_fill_sz));

    DWORD tls_i;
    dbgprintf("TLS index at:       0x%p[0x%08X] -> ",
        tls_i_addr, ADDR2RVA(tls_i_addr, mod_base));
    if (read_memory(tls_i_addr, &tls_i, sizeof(tls_i), &cb) && cb==sizeof(tls_i))
    {
        dbgprintf("0x%08X\n", get_32uint_le(&tls_i));
    } else {
        dbgprintf("???\n");
    }

    dbgprintf("Callbacks at:       0x%p[0x%08X]",
        callbacks_addr, ADDR2RVA(callbacks_addr, mod_base));
    if (callbacks_addr)
    {
        dbgprintf(" ->");
        size_t hndlr_addr_sz = (hndl.nt_hdrs.pe_tpy==pe_32bit ? 4 : 8);

        for (UINT hndlr_i=0;; callbacks_addr+=hndlr_addr_sz, hndlr_i++)
        {
            ULONG64 hndlr_addr;

            if (read_memory(callbacks_addr, &hndlr_addr, hndlr_addr_sz, &cb) &&
                cb==hndlr_addr_sz)
            {
                hndlr_addr = (hndl.nt_hdrs.pe_tpy==pe_32bit ?
                    DEBUG_EXTEND64(get_32uint_le(&hndlr_addr)) :
                    get_64uint_le(&hndlr_addr));

                if (hndlr_addr) dbgprintf(" 0x%p", hndlr_addr);
                else {
                    if (!hndlr_i) dbgprintf(" no handlers");
                    break;
                }
            } else break;
        }
    }
    dbgprintf("\n");

    dbgprintf("Size of zero fill:  0x%08X\n", zero_fill_sz);
    dbgprintf("Characteristics:    0x%08X\n", chrcts);

finish:
    return;
}

/* exported; see header for details */
void print_debug(ULONG64 mod_base, const rng_spec_t *p_rng)
{
    prnt_dir_hndl_t hndl;
    if (!init_prnt_dir_hndl(&hndl, mod_base, IMAGE_DIRECTORY_ENTRY_DEBUG, p_rng))
        goto finish;

    /* print header */
    if (!hndl.dir_addr || (!p_rng && !hndl.dir_sz)) {
        info_dbgprintf("No debug info in this module!\n");
        goto finish;
    } else
        info_dbgprintf("Debug info at: 0x%p\n", hndl.dir_addr);

    info_dbgprintf("RVA provided in []\n\n");

    ULONG cb;
    IMAGE_DEBUG_DIRECTORY debug;
    if (!(read_memory(hndl.dir_addr, &debug, sizeof(debug), &cb) &&
        cb==sizeof(debug))) goto finish;

    dbgprintf("Characteristics: 0x%08X\n", get_32uint_le(&debug.Characteristics));
    dbgprintf("Timestamp:       0x%08X\n", get_32uint_le(&debug.TimeDateStamp));
    dbgprintf("Major version:   0x%04X\n", get_16uint_le(&debug.MajorVersion));
    dbgprintf("Minor version:   0x%04X\n", get_16uint_le(&debug.MinorVersion));

    DWORD type = get_32uint_le(&debug.Type);
    dbgprintf("Type:            0x%08X   ; ", type);

    switch (type)
    {
    default:
    case IMAGE_DEBUG_TYPE_UNKNOWN:
        dbgprintf("unknown\n");
        break;
    case IMAGE_DEBUG_TYPE_COFF:
        dbgprintf("coff\n");
        break;
    case IMAGE_DEBUG_TYPE_CODEVIEW:
        dbgprintf("codeview\n");
        break;
    case IMAGE_DEBUG_TYPE_FPO:
        dbgprintf("fpo\n");
        break;
    case IMAGE_DEBUG_TYPE_MISC:
        dbgprintf("miscellaneous\n");
        break;
    case IMAGE_DEBUG_TYPE_EXCEPTION:
        dbgprintf("exception\n");
        break;
    case IMAGE_DEBUG_TYPE_FIXUP:
        dbgprintf("fixup\n");
        break;
    case IMAGE_DEBUG_TYPE_OMAP_TO_SRC:
        dbgprintf("omap to source\n");
        break;
    case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC:
        dbgprintf("omap from source\n");
        break;
    case IMAGE_DEBUG_TYPE_BORLAND:
        dbgprintf("borland\n");
        break;
    case IMAGE_DEBUG_TYPE_RESERVED10:
        dbgprintf("reserved\n");
        break;
    case IMAGE_DEBUG_TYPE_CLSID:
        dbgprintf("clsid\n");
        break;
    }

    dbgprintf("Size of data:    0x%08X\n", get_32uint_le(&debug.SizeOfData));

    DWORD rva = get_32uint_le(&debug.AddressOfRawData);
    dbgprintf("Address of data: 0x%p[0x%08X]\n", RVA2ADDR(rva, mod_base), rva);

    dbgprintf("Pointer to data: 0x%08X\n", get_32uint_le(&debug.PointerToRawData));

finish:
    return;
}

/* exported; see header for details */
void print_reloc(ULONG64 mod_base, const rng_spec_t *p_rng)
{
    const static str_num_t reloc_tpy_ht[] = {
        {"padding",0}, {"hign",1}, {"low",2}, {"high_low",3},
        {"high_adj (with param on the next slot)",4},
        {"mips_jmp OR arm_mov32a",5}, {"arm_movt",7},
        {"ia64_imm64 OR mips_jmp16",9}, {"dir64",10}};

    prnt_dir_hndl_t hndl;
    if (!init_prnt_dir_hndl(
        &hndl, mod_base, IMAGE_DIRECTORY_ENTRY_BASERELOC, p_rng)) goto finish;

    /* print header */
    if (!hndl.dir_addr || (!p_rng && !hndl.dir_sz)) {
        info_dbgprintf("No base reloc table in this module!\n");
        goto finish;
    } else {
        info_dbgprintf("reloc table at: 0x%p\n", hndl.dir_addr);
    }
    info_dbgprintf("RVA provided in []\n\n");

    DWORD off=0; 
    DWORD len_cnstr = (p_rng ? p_rng->rng.len : hndl.dir_sz);
    IMAGE_BASE_RELOCATION reloc_info;

    for (;;)
    {
        if (len_cnstr!=(DWORD)-1) {
            if (len_cnstr<sizeof(reloc_info)) goto finish;
            len_cnstr-=sizeof(reloc_info);
        }

        ULONG cb;
        ULONG64 reloc_info_addr = hndl.dir_addr+off;
        if (!(read_memory(reloc_info_addr, &reloc_info, sizeof(reloc_info), &cb)
            && cb==sizeof(reloc_info))) goto finish;
        off+=sizeof(reloc_info);

        /* finish on zeroed entry */
        if (!rmemchr(&reloc_info, 0, sizeof(reloc_info))) goto finish;

        DWORD block_rva = get_32uint_le(&reloc_info.VirtualAddress);
        ULONG64 block_addr = RVA2ADDR(block_rva, mod_base);
        DWORD block_sz = get_32uint_le(&reloc_info.SizeOfBlock);
        dbgprintf("0x%p[0x%08X] Base reloc block at 0x%p[0x%08X] with "
            "size 0x%08X\n", reloc_info_addr, ADDR2RVA(reloc_info_addr, mod_base),
            block_addr, block_rva, block_sz);

        block_sz = block_sz-sizeof(reloc_info);
        if (len_cnstr!=(DWORD)-1 && block_sz>len_cnstr) block_sz=len_cnstr;

        UINT n_prm_slot=0;
        WORD rd_buf[0x100];

        while (block_sz)
        {
            ULONG read_sz = (block_sz>sizeof(rd_buf) ? sizeof(rd_buf) : block_sz);

            if (!(read_memory(hndl.dir_addr+off, &rd_buf, read_sz, &cb) &&
                cb==read_sz)) goto finish;
            off+=read_sz;

            for (UINT i=0; i<read_sz/sizeof(rd_buf[0]); i++)
            {
                WORD reloc_i = get_16uint_le(&rd_buf[i]);
                if (!n_prm_slot)
                {
                    UINT block_off = reloc_i&0xfff;
                    UINT reloc_tpy = (reloc_i>>12)&0x0f;
                    dbgprintf("  Reloc at: 0x%p[0x%08X+0x%03X], type: 0x%X   ; %s\n",
                        block_addr+block_off, block_rva, block_off, reloc_tpy,
                        get_ht_str(reloc_tpy_ht,
                            sizeof(reloc_tpy_ht)/sizeof(reloc_tpy_ht[0]),
                            reloc_tpy, "???"));

                    if (reloc_tpy==IMAGE_REL_BASED_HIGHADJ) n_prm_slot=1;
                } else {
                    dbgprintf("  Param slot: 0x%04X\n", (UINT)reloc_i);
                    n_prm_slot--;
                }
            }

            block_sz-=read_sz;
            if (len_cnstr!=(DWORD)-1) len_cnstr-=read_sz;
        }
    }

finish:
    return;
}

/* Free dump_pe_hndl_t handle */
static void free_dump_pe_hndl(dump_pe_hndl_t *p_hndl)
{
    if (p_hndl->f_out) {
        fclose(p_hndl->f_out);
        p_hndl->f_out=NULL;
    }

    for (DWORD i=0; i<p_hndl->n_sects; i++) {
        if (p_hndl->sect_dmpcfg[i].tpy==secdmp_file &&
            p_hndl->sect_dmpcfg[i].dmpfile.fh)
        {
            fclose(p_hndl->sect_dmpcfg[i].dmpfile.fh);
            p_hndl->sect_dmpcfg[i].dmpfile.fh = NULL;
            p_hndl->sect_dmpcfg[i].dmpfile.fsz = 0;
        }
    }
}

/* Init dump_pe_hndl_t handle; return TRUE on success */
static BOOL init_dump_pe_hndl(
    dump_pe_hndl_t *p_hndl, ULONG64 mod_base, BOOL b_open_outf)
{
    BOOL ret=FALSE;

    memset(p_hndl, 0, sizeof(*p_hndl));

    p_hndl->mod_base = mod_base;

    if (b_open_outf) {
        GetPrivateProfileString(PROP_SECT_DUMP, PROP_DUMP_OUTPUT, OUT_DUMP_DEF_FILE,
            p_hndl->f_out_name, sizeof(p_hndl->f_out_name), PROP_FILE);

        if (!(p_hndl->f_out = fopen(p_hndl->f_out_name, "w+b"))) {
            err_dbgprintf("Can't open dump output file %s\n", p_hndl->f_out_name);
            goto finish;
        }
    } else {
        *p_hndl->f_out_name = 0;
        p_hndl->f_out = NULL;
    }

    ULONG64 sectab_addr;
    if (!read_pe_headers(mod_base, &p_hndl->dos_hdr,
        &p_hndl->nt_hdrs, &sectab_addr, TRUE)) goto finish;

    p_hndl->n_sects = read_sectab(
        &p_hndl->nt_hdrs, sectab_addr, p_hndl->sectab, TRUE, TRUE);

    /* all sects set to memory dump */

    ret=TRUE;
finish:
    if (!ret) free_dump_pe_hndl(p_hndl);
    return ret;
}

/* Print warn message if the pointer 'ptr' points outside the sections table.
   Type of the pointer 'ptr' is either RVA or raw file pointer (as indicated by
   the 'ptrtpy'). If sz>0 then additionally check inclusion in the owning
   section/header of a block 'sz' long (starting from 'ptr').
 */
static void check_ref(const dump_pe_hndl_t *p_hndl, DWORD ptr, pe_ptrtpy_t ptrtpy,
    DWORD sz, const char *pc_hdr_name, const char *pc_fld_name)
{
    ownfo_tpy_t ownfo_tpy;
    char sect_info[100];
    *sect_info=0;

    get_owner_info(p_hndl->mod_base, &p_hndl->nt_hdrs, sect_info,
        p_hndl->sectab, p_hndl->n_sects, ptr, ptrtpy, sz, &ownfo_tpy);

    if (ownfo_tpy!=ownfo_info_cont)
            warn_dbgprintf("%s/%s%s\n", pc_hdr_name, pc_fld_name, sect_info);
}

#define CHKREF_HEADERS      0x01U
#define CHKREF_SECTS        0x02U
#define CHKREF_DIRS         0x04U

/* Check references to sections table and print warnings in case of detections
   of problems. 'what' is a bitmap specifying what type of checking shall be
   performed (CHK_REF_XXX or-ed flags). If PE directories have been chosen to check,
   'not_dirs' as a bitmap, specifies what dirs NOT to check (1st dir at bit 0,
   2nd at bit 1 and so on).
 */
static void check_refs(const dump_pe_hndl_t *p_hndl, UINT what, UINT32 not_dirs)
{
    DWORD rptr, rva;

    /* check headers */
    if (what & CHKREF_HEADERS)
    {
        /* no need to check references by raw pointers of
           PointerToSymbolTable since it may points to region outside PE sections */

        rva = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
            get_32uint_le(
                &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.AddressOfEntryPoint):
            get_32uint_le(
                &p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.AddressOfEntryPoint));
        if (rva) {
            check_ref(p_hndl,
                rva, pe_ptrtpy_rva, 0, PROP_SECT_OPTH, PROP_OPTH_ENTRY_POINT);
        }

        rva = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
            get_32uint_le(&p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.BaseOfCode):
            get_32uint_le(&p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.BaseOfCode));
        if (rva) {
            check_ref(p_hndl,
                rva, pe_ptrtpy_rva, 0, PROP_SECT_OPTH, PROP_OPTH_BASE_CODE);
        }

        if (p_hndl->nt_hdrs.pe_tpy==pe_32bit) {
            if (rva = get_32uint_le(
                &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.BaseOfData))
            {
                check_ref(p_hndl,
                    rva, pe_ptrtpy_rva, 0, PROP_SECT_OPTH, PROP_OPTH_BASE_DATA);
            }
        }
    }

    /* no need to check references by sections raw pointers of PointerToRelocations
       and PointerToLinenumbers since they may points to regions outside PE
       sections */

    /* check references to RVA fields in the PE directories */
    if (what & CHKREF_DIRS)
    {
        DWORD num_dir_ents =
            (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
            get_32uint_le(
                &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.NumberOfRvaAndSizes):
            get_32uint_le(
                &p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.NumberOfRvaAndSizes));

        for (DWORD i=0; i<num_dir_ents; i++)
        {
            if (i==IMAGE_DIRECTORY_ENTRY_SECURITY) {
                /* security may points to regions outside
                   PE sections - no need to check */
                continue;
            }
            if (not_dirs & (1<<i)) {
                /* checking disabled */
                continue;
            }

            const IMAGE_DATA_DIRECTORY *p_dir_ent =
                (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
                &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.DataDirectory[i]:
                &p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.DataDirectory[i]);

            char prm_name[32];
            get_dir_fld_name(i, dirfld_rva, prm_name);

            if (rva = get_32uint_le(&p_dir_ent->VirtualAddress)) {
                check_ref(p_hndl, rva, pe_ptrtpy_rva,
                    get_32uint_le(&p_dir_ent->Size), PROP_SECT_DIRS, prm_name);
            }
        }
    }
}

/* Updates sizes in PE headers as indicated by the input params */
static void update_pe_sizes(dump_pe_hndl_t *p_hndl,
    DWORD code_sz, DWORD initdt_sz, DWORD uninitdt_sz, DWORD img_sz)
{
    DWORD org_code_sz = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
        get_32uint_le(&p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.SizeOfCode):
        get_32uint_le(&p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.SizeOfCode));
    if (org_code_sz!=code_sz)
    {
        info_dbgprintf("Updated %s/SizeOfCode from 0x%08X to 0x%08X\n",
            PROP_SECT_OPTH, org_code_sz, code_sz);
        if (p_hndl->nt_hdrs.pe_tpy==pe_32bit) {
            set_32uint_le(
                &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.SizeOfCode, code_sz);
        } else {
            set_32uint_le(
                &p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.SizeOfCode, code_sz);
        }
    }
    DWORD org_initdt_sz = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
        get_32uint_le(
            &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.SizeOfInitializedData):
        get_32uint_le(
            &p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.SizeOfInitializedData));
    if (org_initdt_sz!=initdt_sz)
    {
        info_dbgprintf("Updated %s/SizeOfInitializedData from 0x%08X to 0x%08X\n",
            PROP_SECT_OPTH, org_initdt_sz, initdt_sz);
        if (p_hndl->nt_hdrs.pe_tpy==pe_32bit) {
            set_32uint_le(
                &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.SizeOfInitializedData,
                initdt_sz);
        } else {
            set_32uint_le(
                &p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.SizeOfInitializedData,
                initdt_sz);
        }
    }
    DWORD org_uninitdt_sz = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
        get_32uint_le(
            &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.SizeOfUninitializedData):
        get_32uint_le(
            &p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.SizeOfUninitializedData));
    if (org_uninitdt_sz!=uninitdt_sz)
    {
        info_dbgprintf("Updated %s/SizeOfUninitializedData from 0x%08X to 0x%08X\n",
            PROP_SECT_OPTH, org_uninitdt_sz, uninitdt_sz);
        if (p_hndl->nt_hdrs.pe_tpy==pe_32bit) {
            set_32uint_le(
                &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.SizeOfUninitializedData,
                uninitdt_sz);
        } else {
            set_32uint_le(
                &p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.SizeOfUninitializedData,
                uninitdt_sz);
        }
    }
    DWORD org_img_sz = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
        get_32uint_le(
            &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.SizeOfImage):
        get_32uint_le(
            &p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.SizeOfImage));
    if (org_img_sz!=img_sz)
    {
        info_dbgprintf("Updated %s/SizeOfImage from 0x%08X to 0x%08X\n",
            PROP_SECT_OPTH, org_img_sz, img_sz);
        if (p_hndl->nt_hdrs.pe_tpy==pe_32bit) {
            set_32uint_le(
                &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.SizeOfImage, img_sz);
        } else {
            set_32uint_le(
                &p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.SizeOfImage, img_sz);
        }
    }
}

/* Read conf for the PE headers. PE CRC is also cleared */
static void read_headers_cfg(dump_pe_hndl_t *p_hndl)
{
    /* clear PointerToSymbolTable since it may (and usually does)
       points to region outside PE sections */
    set_32uint_le(&get_FileHeader(&p_hndl->nt_hdrs).PointerToSymbolTable, 0);

    DWORD entry_point = GetPrivateProfileInt(
        PROP_SECT_OPTH, PROP_OPTH_ENTRY_POINT, -1, PROP_FILE);
    if (entry_point!=(DWORD)-1)
    {
        if (p_hndl->nt_hdrs.pe_tpy==pe_32bit) {
            set_32uint_le(
                &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.AddressOfEntryPoint,
                entry_point);
        } else {
            set_32uint_le(
                &p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.AddressOfEntryPoint,
                entry_point);
        }
        info_dbgprintf("%s/%s = 0x%08X\n",
            PROP_SECT_OPTH, PROP_OPTH_ENTRY_POINT, entry_point);
    }
    DWORD base_code = GetPrivateProfileInt(
        PROP_SECT_OPTH, PROP_OPTH_BASE_CODE, -1, PROP_FILE);
    if (base_code!=(DWORD)-1)
    {
        if (p_hndl->nt_hdrs.pe_tpy==pe_32bit) {
            set_32uint_le(
                &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.BaseOfCode, base_code);
        } else {
            set_32uint_le(
                &p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.BaseOfCode, base_code);
        }
        info_dbgprintf("%s/%s = 0x%08X\n",
            PROP_SECT_OPTH, PROP_OPTH_BASE_CODE, base_code);
    }
    if (p_hndl->nt_hdrs.pe_tpy==pe_32bit)
    {
        DWORD base_data = GetPrivateProfileInt(
            PROP_SECT_OPTH, PROP_OPTH_BASE_DATA, -1, PROP_FILE);
        if (base_data!=(DWORD)-1)
        {
            set_32uint_le(
                &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.BaseOfData, base_data);
            info_dbgprintf(
                "%s/%s = 0x%08X\n", PROP_SECT_OPTH, PROP_OPTH_BASE_DATA, base_data);
        }
    }

    /* clear the PE checksum */
    if (p_hndl->nt_hdrs.pe_tpy==pe_32bit)
        set_32uint_le(&p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.CheckSum, 0);
    else
        set_32uint_le(&p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.CheckSum, 0);
}

/* Read conf for the PE directories. */
static void read_dirs_cfg(dump_pe_hndl_t *p_hndl)
{
    DWORD num_dir_ents =
        (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
        get_32uint_le(
            &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.NumberOfRvaAndSizes):
        get_32uint_le(
            &p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.NumberOfRvaAndSizes));

    IMAGE_DATA_DIRECTORY *p_dd;
    for (UINT i=0; i<num_dir_ents; i++)
    {
        if (get_data_dir(&p_hndl->nt_hdrs, i, &p_dd, FALSE))
        {
            if (i==15) {
                /* some packers modify reserved 15th dir; fix
                   it to zero as the PE specification states */
                set_32uint_le(&p_dd->VirtualAddress, 0);
                set_32uint_le(&p_dd->Size, 0);
            } else
            {
                BOOL modified=FALSE;
                char prm_name[32], prm_val[32];

                /* rva */
                get_dir_fld_name(i, dirfld_rva, prm_name);
                if (GetPrivateProfileString(PROP_SECT_DIRS,
                    prm_name, "", prm_val, sizeof(prm_val), PROP_FILE)>0)
                {
                    modified=TRUE;
                    if (i!=IMAGE_DIRECTORY_ENTRY_IMPORT ||
                        strcmp(prm_val, IDT_AFTER_IAT))
                    {
                        DWORD rva = strtoul(prm_val, NULL, 0);
                        set_32uint_le(&p_dd->VirtualAddress, rva);
                        info_dbgprintf("%s/%s = 0x%08X\n",
                            PROP_SECT_DIRS, prm_name, rva);
                    }
                    /* "afer_iat" spec. case will be recognized by
                        the imports patching func */
                }

                /* size */
                get_dir_fld_name(i, dirfld_size, prm_name);
                DWORD sz = GetPrivateProfileInt(
                    PROP_SECT_DIRS, prm_name, -1, PROP_FILE);
                if (sz!=(DWORD)-1)
                {
                    modified=TRUE;
                    set_32uint_le(&p_dd->Size, sz);
                    info_dbgprintf(
                        "%s/%s = 0x%08X\n", PROP_SECT_DIRS, prm_name, sz);
                }

                /* if conf doesn't state otherwise clear Certificates &
                   BoundImports dirs */
                if (!modified)
                {
                    if (i==IMAGE_DIRECTORY_ENTRY_SECURITY) {
                        /* remove digital sign */
                        set_32uint_le(&p_dd->VirtualAddress, 0);
                        set_32uint_le(&p_dd->Size, 0);
                    } else
                    if (i==IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT) {
                        /* clear bound imports (it will be rebuild later on) */
                        set_32uint_le(&p_dd->VirtualAddress, 0);
                        set_32uint_le(&p_dd->Size, 0);
                    }
                }

                /* read debug data */
                if (i==IMAGE_DIRECTORY_ENTRY_DEBUG) {
                    DWORD dbg_rva = get_32uint_le(&p_dd->VirtualAddress);
                    ULONG64 dbg_addr = RVA2ADDR(dbg_rva, p_hndl->mod_base);

                    if (dbg_rva) {
                        ULONG cb;
                        if (read_memory(dbg_addr,
                                &p_hndl->debug, sizeof(p_hndl->debug), &cb) &&
                            cb==sizeof(p_hndl->debug))
                        {
                            p_hndl->debug_addr = dbg_addr;

                            DWORD dta_rptr;
                            DWORD dta_rva =
                                get_32uint_le(&p_hndl->debug.AddressOfRawData);

                            if (!(dta_rva &&
                                get_raw_ptr(
                                    p_hndl, dta_rva, &dta_rptr, NULL, NULL) &&
                                dta_rptr && (dta_rptr==get_32uint_le(
                                    &p_hndl->debug.PointerToRawData))))
                            {
                                /* clear the raw pointer since it may point to a
                                   PE file region not mapped to memory, therefore
                                   not able to be properly recovered during the
                                   dumping process */
                                set_32uint_le(&p_hndl->debug.PointerToRawData, 0);
                            }
                        }
                    }
                }
            }
        }
    }
}

/* Get a size of memory block with the beginning at address 'addr' and size 'sz'
   without trailing zero bytes. In case of read memory problem the func returns
   'sz'
 */
static DWORD trimmed_zeros_sz(ULONG64 addr, DWORD sz)
{
    DWORD ret=sz;
    UINT8 rd_buf[0x1000];
    ULONG64 rd_addr = addr+sz;

    if (!addr) goto finish;

    for (DWORD rem_sz=sz; rem_sz;)
    {
        ULONG cb;
        DWORD rd_sz = (rem_sz>=sizeof(rd_buf) ? sizeof(rd_buf) : rem_sz);
        rd_addr -= rd_sz;

        if (!(read_memory(rd_addr, rd_buf, rd_sz, &cb) && cb==rd_sz))
            goto finish;

        for (DWORD i=0; i<rd_sz; i++) {
            if (rd_buf[rd_sz-1-i]) {
                ret = rem_sz-i;
                goto finish;
            }
        }
        rem_sz -= rd_sz;
    }

    /* whole range consists of zeros */
    ret = 0;

finish:
    return ret;
}

/* Support func for read_sects_cfg() */
static BOOL read_sect_dmpcfg(dump_pe_hndl_t *p_hndl, DWORD sect_i)
{
    BOOL ret=FALSE;
    char prm_name[32], prm_val[MAX_PATH+8];

    /* set default value */
    p_hndl->sect_dmpcfg[sect_i].tpy = secdmp_mem;

    sprintf(prm_name, "%d.%s", sect_i+1, PROP_SECTS_DMPCONT);
    if (GetPrivateProfileString(
        PROP_SECT_SECTS, prm_name, "", prm_val, sizeof(prm_val), PROP_FILE)>0)
    {
        prm_val[sizeof(prm_val)-1] = 0;

        if (!strcmpi(prm_val, DMPCONT_MEM)) {
            info_dbgprintf("%s/%s = %s\n", PROP_SECT_SECTS, prm_name, prm_val);
        } else
        if (!strcmpi(prm_val, DMPCONT_ZEROS)) {
            p_hndl->sect_dmpcfg[sect_i].tpy = secdmp_zeros;
            info_dbgprintf("%s/%s = %s\n", PROP_SECT_SECTS, prm_name, prm_val);
        } else
        {
            size_t pref_len = strlen(DMPCONT_FILE);
            size_t val_len = strlen(prm_val);

            char tmp = prm_val[pref_len];
            prm_val[pref_len]=0;
            if (val_len>=pref_len && !strcmpi(prm_val, DMPCONT_FILE))
            {
                prm_val[pref_len]=tmp;
                const char *pc_fname = &prm_val[pref_len];
                for (; isspace(*pc_fname); pc_fname++);

                FILE *fh = fopen(pc_fname, "rb");
                if (!fh) {
                    err_dbgprintf(
                        "Open file [%s] error: %s\n", pc_fname, strerror(errno));
                    goto finish;
                }

                long int fsz;
                if (fseek(fh, 0, SEEK_END) ||
                    (fsz=ftell(fh))==-1L ||
                    fseek(fh, 0, SEEK_SET))
                {
                    fclose(fh);
                    err_dbgprintf("File [%s] access error\n", pc_fname);
                    goto finish;
                }

                p_hndl->sect_dmpcfg[sect_i].tpy = secdmp_file;
                p_hndl->sect_dmpcfg[sect_i].dmpfile.fh = fh;
                p_hndl->sect_dmpcfg[sect_i].dmpfile.fsz = (ULONG)fsz;

                info_dbgprintf("%s/%s = %s %s   ; file length: %lu\n",
                    PROP_SECT_SECTS, prm_name, DMPCONT_FILE, pc_fname, (ULONG)fsz);
            }
        }
    }

    ret=TRUE;
finish:
    return ret;
}

/* Update raw sizes after PE file raw modification; support func for
   read_sects_cfg() */
static void update_raw_sizes(dump_pe_hndl_t *p_hndl, DWORD upd_rptr, DWORD delta)
{
    if (delta && upd_rptr)
    {
        /* PointerToSymbolTable */
        DWORD rptr = get_32uint_le(
            &get_FileHeader(&p_hndl->nt_hdrs).PointerToSymbolTable);

        if (rptr && upd_rptr<=rptr) {
            set_32uint_le(&get_FileHeader(&p_hndl->nt_hdrs).PointerToSymbolTable,
                (DWORD)(rptr+delta));
        }

        /* security dir entry */
        IMAGE_DATA_DIRECTORY *p_dd;
        if (get_data_dir(
                &p_hndl->nt_hdrs, IMAGE_DIRECTORY_ENTRY_SECURITY, &p_dd, FALSE) &&
            (rptr=get_32uint_le(&p_dd->VirtualAddress)) && upd_rptr<=rptr)
        {
            set_32uint_le(&p_dd->VirtualAddress, (DWORD)(rptr+delta));
        }

        /* update raw pointer to the debug data */
        if (p_hndl->debug_addr) {
            if ((rptr=get_32uint_le(
                &p_hndl->debug.PointerToRawData)) && upd_rptr<=rptr) {
                set_32uint_le(
                    &p_hndl->debug.PointerToRawData, (DWORD)(rptr+delta));
            }
        }

        for (DWORD i=0; i<p_hndl->n_sects; i++)
        {
            /* PointerToRawData */
            rptr = get_32uint_le(&p_hndl->sectab[i].PointerToRawData);
            if (rptr && upd_rptr<=rptr) {
                set_32uint_le(
                    &p_hndl->sectab[i].PointerToRawData, (DWORD)(rptr+delta));
            }

            /* PointerToRelocations */
            rptr = get_32uint_le(&p_hndl->sectab[i].PointerToRelocations);
            if (rptr && upd_rptr<=rptr) {
                set_32uint_le(
                    &p_hndl->sectab[i].PointerToRelocations, (DWORD)(rptr+delta));
            }

            /* PointerToLinenumbers */
            rptr = get_32uint_le(&p_hndl->sectab[i].PointerToLinenumbers);
            if (rptr && upd_rptr<=rptr) {
                set_32uint_le(
                    &p_hndl->sectab[i].PointerToLinenumbers, (DWORD)(rptr+delta));
            }
        }
    }
}

/* Find a raw file sect. start for an inserted section located after section
   'sect_i' (0-based); Returned offset is always >0. Support func for
   read_sects_cfg()
 */
static DWORD get_ins_sect_rptr(const dump_pe_hndl_t *p_hndl, DWORD sect_i)
{
    DWORD rptr=0;

    if (!sect_i) {
first_sect:
        /* the 1st sect. inserted; returned raw ptr is
           the raw ptr of the following, non-zero sections */
        for (DWORD i=0; i<p_hndl->n_sects; i++) {
            DWORD rptr_i = p_hndl->sectab[i].PointerToRawData;
            if (rptr_i) {
                rptr = rptr_i;
                break;
            }
        }
    } else {
        /* raw ptr bases on the end of the preceding, non-zero raw sect */
        DWORD i=sect_i-1;
        do {
            DWORD rptr_i = p_hndl->sectab[i].PointerToRawData;
            if (rptr_i) {
                rptr = rptr_i + p_hndl->sectab[i].SizeOfRawData;
                break;
            }
        } while (i--);

        /* if all preceding sects are empty, act as for the 1st section */
        if (!rptr) goto first_sect;
    }

    if (!rptr) {
        /* PE file w/o raw sections!; take a value as the PE headers size */
        rptr = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
            get_32uint_le(&p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.SizeOfHeaders) :
            get_32uint_le(&p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.SizeOfHeaders));
    }

    return rptr;
}

/* Update section 'sect_i' according to its configuration. Support
   func for read_sects_cfg(). Returns TRUE on success, FALSE otherwise.
 */
static BOOL update_sect(
    dump_pe_hndl_t *p_hndl, DWORD sect_i, BOOL rsz_auto_all, BOOL rsz_vsz_all)
{
    BOOL ret=FALSE;
    char prm_name[32], prm_val[128];

    /* Name */
    sprintf(prm_name, "%d.%s", sect_i+1, PROP_SECTS_NAME);
    memset(prm_val, 0, IMAGE_SIZEOF_SHORT_NAME);
    if (GetPrivateProfileString(
        PROP_SECT_SECTS, prm_name, "", prm_val, sizeof(prm_val), PROP_FILE)>0)
    {
        prm_val[IMAGE_SIZEOF_SHORT_NAME] = 0;
        strncpy((char*)&p_hndl->sectab[sect_i].Name[0],
            prm_val, IMAGE_SIZEOF_SHORT_NAME);
        info_dbgprintf("%s/%s = %s\n", PROP_SECT_SECTS, prm_name, prm_val);
    }

    /* Characteristics */
    sprintf(prm_name, "%d.%s", sect_i+1, PROP_SECTS_CHARACTER);
    if (GetPrivateProfileString(
        PROP_SECT_SECTS, prm_name, "", prm_val, sizeof(prm_val), PROP_FILE)>0)
    {
        DWORD chrt = parse_flags(SECCHRVALS_HT, NUM_SECCHRVALS, prm_val);
        set_32uint_le(&p_hndl->sectab[sect_i].Characteristics, chrt);

        info_dbgprintf("%s/%s = 0x%08X", PROP_SECT_SECTS, prm_name, chrt);
        print_flags(SECCHRVALS_HT, NUM_SECCHRVALS, chrt, 32);
    }

    if (!read_sect_dmpcfg(p_hndl, sect_i)) goto finish;
    sect_dump_tpy_t dmptpy = p_hndl->sect_dmpcfg[sect_i].tpy;

    /* VirtualAddress */
    sprintf(prm_name, "%d.%s", sect_i+1, PROP_SECTS_RVA);

    DWORD sect_rva = GetPrivateProfileInt(
        PROP_SECT_SECTS, prm_name, -1, PROP_FILE);
    if (sect_rva!=(DWORD)-1) {
        set_32uint_le(&p_hndl->sectab[sect_i].VirtualAddress, sect_rva);
        info_dbgprintf("%s/%s = 0x%08X\n", PROP_SECT_SECTS, prm_name, sect_rva);
    }

    /* VirtualSize */
    sprintf(prm_name, "%d.%s", sect_i+1, PROP_SECTS_VSZ);

    BOOL sect_cfg = (GetPrivateProfileString(
        PROP_SECT_SECTS, prm_name, "", prm_val, sizeof(prm_val), PROP_FILE)>0);
    if (sect_cfg || dmptpy==secdmp_file)
    {
        DWORD vsz = (sect_cfg ? strtoul(prm_val, NULL, 0) :
            p_hndl->sect_dmpcfg[sect_i].dmpfile.fsz);

        set_32uint_le(&p_hndl->sectab[sect_i].Misc.VirtualSize, vsz);
        info_dbgprintf("%s/%s = 0x%08X\n", PROP_SECT_SECTS, prm_name, vsz);
    }

    /* fix malformed empty virt. mem. range */
    if (!get_32uint_le(&p_hndl->sectab[sect_i].VirtualAddress) ||
        !get_32uint_le(&p_hndl->sectab[sect_i].Misc.VirtualSize))
    {
        set_32uint_le(&p_hndl->sectab[sect_i].VirtualAddress, 0);
        set_32uint_le(&p_hndl->sectab[sect_i].Misc.VirtualSize, 0);
    }

    /* SizeOfRawData */
    sprintf(prm_name, "%d.%s", sect_i+1, PROP_SECTS_RSZ);
    sect_cfg = (GetPrivateProfileString(
        PROP_SECT_SECTS, prm_name, "", prm_val, sizeof(prm_val), PROP_FILE)>0);

    if (sect_cfg || rsz_auto_all || rsz_vsz_all || dmptpy==secdmp_file)
    {
        DWORD upd_rptr;
        DWORD prev_rsz = get_32uint_le(&p_hndl->sectab[sect_i].SizeOfRawData);

        if (!prev_rsz) {
            /* inserting a raw file section which is currently absent in the file */
            upd_rptr = get_ins_sect_rptr(p_hndl, sect_i);
        } else {
            upd_rptr = get_32uint_le(
                &p_hndl->sectab[sect_i].PointerToRawData) + prev_rsz;
        }

        /* get raw size */
        DWORD rsz=(DWORD)-1;
        BOOL rsz_auto=rsz_auto_all, rsz_vsz=rsz_vsz_all;

        if (sect_cfg) {
            /* particular section's conf has a precedence over global conf */
            rsz_auto=rsz_vsz=FALSE;

            if (!strcmpi(prm_val, RSZ_AUTO)) rsz_auto=TRUE;
            else
            if (!strcmpi(prm_val, RSZ_AS_VSZ)) rsz_vsz=TRUE;
            else {
                /* directly provided raw size */
                rsz = strtoul(prm_val, NULL, 0);
            }
        } else
        if (dmptpy==secdmp_file) {
            rsz = p_hndl->sect_dmpcfg[sect_i].dmpfile.fsz;
        }

        if (rsz==(DWORD)-1)
        {
            if (rsz_auto)
            {
                if (dmptpy!=secdmp_mem) {
                    err_dbgprintf("The \"auto\" mode may be used only for memory "
                        "dumps. Provide other specification of \"SizeOfRawData\" "
                        "for section %d\n", sect_i+1);
                    goto finish;
                }

                ULONG64 sect_addr = RVA2ADDR(get_32uint_le(
                    &p_hndl->sectab[sect_i].VirtualAddress), p_hndl->mod_base);
                DWORD setc_vsz =
                    get_32uint_le(&p_hndl->sectab[sect_i].Misc.VirtualSize);
                rsz = trimmed_zeros_sz(sect_addr, setc_vsz);
            } else
            if (rsz_vsz) {
                rsz = get_32uint_le(&p_hndl->sectab[sect_i].Misc.VirtualSize);
            }
        }

        DWORD file_algn = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
            get_32uint_le(&p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.FileAlignment) :
            get_32uint_le(&p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.FileAlignment));

        rsz = RNDUP(rsz, file_algn);
        DWORD raw_delta = rsz-prev_rsz;

        /* if raw size has been changed we need to recalculate
           all raw offsets in the file header and sections */
        update_raw_sizes(p_hndl, upd_rptr, raw_delta);

        set_32uint_le(&p_hndl->sectab[sect_i].SizeOfRawData, rsz);
        info_dbgprintf("%s/%s = 0x%08X\n", PROP_SECT_SECTS, prm_name, rsz);

        if (rsz && !prev_rsz) {
            /* a new raw file section need to be inserted */
            set_32uint_le(&p_hndl->sectab[sect_i].PointerToRawData, upd_rptr);
            info_dbgprintf("Inserted a new raw file section %d starting at: "
                "0x%08X, size: 0x%08X\n", sect_i+1, upd_rptr, rsz);
        }

        /* fix malformed empty raw file range */
        if (!get_32uint_le(&p_hndl->sectab[sect_i].SizeOfRawData) ||
            !get_32uint_le(&p_hndl->sectab[sect_i].PointerToRawData))
        {
            set_32uint_le(&p_hndl->sectab[sect_i].SizeOfRawData, 0);
            set_32uint_le(&p_hndl->sectab[sect_i].PointerToRawData, 0);
        }
    }
    ret=TRUE;

finish:
    return ret;
}

/* Read conf for the sections table */
static BOOL read_sects_cfg(dump_pe_hndl_t *p_hndl)
{
    BOOL ret=FALSE;
    DWORD n_sects = p_hndl->n_sects;

    /* RemoveTrailingSections */
    DWORD del_trail_sects = GetPrivateProfileInt(
        PROP_SECT_SECTS, PROP_SECTS_DEL_TRAILING_SECS, 0, PROP_FILE);
    if (del_trail_sects>0) {
        if (del_trail_sects > p_hndl->n_sects) del_trail_sects=p_hndl->n_sects;
        p_hndl->n_sects -= del_trail_sects;

        set_16uint_le(&get_FileHeader(&p_hndl->nt_hdrs).NumberOfSections,
            (UINT16)p_hndl->n_sects);
        info_dbgprintf(
            "Removed %d trailing section(s); current sections table size: %d\n",
            del_trail_sects, p_hndl->n_sects);
    }

    /* clear PointerToRelocations, PointerToLinenumbers since they may
      (and usually do) point to regions outside PE sections */
    for (DWORD i=0; i<p_hndl->n_sects; i++) {
        set_32uint_le(&p_hndl->sectab[i].PointerToRelocations, 0);
        set_32uint_le(&p_hndl->sectab[i].PointerToLinenumbers, 0);
    }

    /* read the global config (related to all sections) */
    BOOL rsz_auto_all=FALSE, rsz_vsz_all=FALSE;
    char prm_name[32], prm_val[128];

    if (GetPrivateProfileString(PROP_SECT_SECTS,
        PROP_SECTS_RSZ, "", prm_val, sizeof(prm_val), PROP_FILE)>0)
    {
        if (!strcmpi(prm_val, RSZ_AUTO)) rsz_auto_all=TRUE;
        else
        if (!strcmpi(prm_val, RSZ_AS_VSZ)) rsz_vsz_all=TRUE;
    }

    DWORD hdrs_sz = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
        get_32uint_le(&p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.SizeOfHeaders) :
        get_32uint_le(&p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.SizeOfHeaders));

    /* go through all the sections reading config for their attributes */
    for (DWORD i=0, n_new_sects=0;; i++)
    {
        if (i < p_hndl->n_sects) {
            /* modify a section in the sections table */
            if (!update_sect(p_hndl, i, rsz_auto_all, rsz_vsz_all))
                goto finish;
        } else
        {
            /* check is there exist a section specification to append
             */
            BOOL b_filedmp=FALSE, b_sects_prms=FALSE;
            const char *sects_prms_names[] = {
                PROP_SECTS_NAME,
                PROP_SECTS_CHARACTER,
                PROP_SECTS_VSZ,
                PROP_SECTS_RVA,
                PROP_SECTS_RSZ,
                PROP_SECTS_DMPCONT};

            for (DWORD j=0;
                j<sizeof(sects_prms_names)/sizeof(sects_prms_names[0]); j++)
            {
                sprintf(prm_name, "%d.%s", i+1, sects_prms_names[j]);
                if (GetPrivateProfileString(PROP_SECT_SECTS,
                    prm_name, "", prm_val, sizeof(prm_val), PROP_FILE)>0)
                {
                    b_sects_prms=TRUE;
                    break;
                }
            }

            if (b_sects_prms>0)
            {
                info_dbgprintf(
                    "Appending section %d to the sections table...\n", i+1);
                if (i<MAX_SECTIONS)
                {
                    memset(&p_hndl->sectab[i], 0, sizeof(p_hndl->sectab[i])); 

                    p_hndl->n_sects++;
                    set_16uint_le(
                        &get_FileHeader(&p_hndl->nt_hdrs).NumberOfSections,
                        (UINT16)p_hndl->n_sects);

                    if (!update_sect(p_hndl, i, rsz_auto_all, rsz_vsz_all))
                        goto finish;

                    n_new_sects++;
                } else {
                    err_dbgprintf(
                        "Number of sections to append exceed %d\n", MAX_SECTIONS);
                    goto finish;
                }
            } else
            {
                /* no additional sect. specification */
                if (n_new_sects)
                {
                    /* update headers size if necessary */
                    DWORD file_algn = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
                        get_32uint_le(
                            &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.FileAlignment) :
                        get_32uint_le(
                            &p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.FileAlignment));
                    DWORD hdrs_off =
                        get_32uint_le(&p_hndl->dos_hdr.e_lfanew) +
                        sizeof(get_Signature(&p_hndl->nt_hdrs)) +
                        sizeof(get_FileHeader(&p_hndl->nt_hdrs)) +
                        get_16uint_le(
                            &get_FileHeader(&p_hndl->nt_hdrs).SizeOfOptionalHeader);
                    DWORD sects_sz = p_hndl->n_sects*sizeof(p_hndl->sectab[0]);

                    if (hdrs_off+sects_sz > hdrs_sz)
                    {
                        DWORD new_hdrs_sz = RNDUP(hdrs_off+sects_sz, file_algn);

                        if (get_rva_info(p_hndl->sectab, p_hndl->n_sects,
                            new_hdrs_sz, NULL, NULL, NULL, NULL))
                        {
                            err_dbgprintf("Sections table with appended sections "
                                "overlaps other sections content\n");
                            goto finish;
                        }

                        update_raw_sizes(p_hndl, new_hdrs_sz, new_hdrs_sz-hdrs_sz);

                        hdrs_sz = new_hdrs_sz;
                        if (p_hndl->nt_hdrs.pe_tpy==pe_32bit) {
                            set_32uint_le(
                                &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.FileAlignment,
                                new_hdrs_sz);
                        } else {
                            set_32uint_le(
                                &p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.FileAlignment,
                                new_hdrs_sz);
                        }
                    }
                }
                break;
            }
        }
    }

    DWORD sect_algn = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
        get_32uint_le(&p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.SectionAlignment) :
        get_32uint_le(&p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.SectionAlignment));

    DWORD i, n_del;
    DWORD code_sz=0, initdt_sz=0, uninitdt_sz=0, img_sz=RNDUP(hdrs_sz, sect_algn);

    /* finally go through reconfigured sections to recalculate
       PE internal sizes and remove unnecessary sections */
    for (i=0, n_del=0; i<p_hndl->n_sects;)
    {
        DWORD sect_rsz = get_32uint_le(&p_hndl->sectab[i].SizeOfRawData);
        DWORD sect_vsz = get_32uint_le(&p_hndl->sectab[i].Misc.VirtualSize);
        DWORD rnd_sect_vsz = RNDUP(sect_vsz, sect_algn);

        /* remove sects which don't exist in a file & mem */
        if (!sect_rsz && !sect_vsz)
        {
            n_del++;
            info_dbgprintf("Empty section detected and removed\n");

            DWORD j;
            for (j=i+1; j<p_hndl->n_sects; j++)
                p_hndl->sectab[j-1]=p_hndl->sectab[j];

            (p_hndl->n_sects)--;
            memset(&p_hndl->sectab[j], 0, sizeof(p_hndl->sectab[j]));

            continue;
        }

        /* re-calc sizes */
        DWORD chrt = get_32uint_le(&p_hndl->sectab[i].Characteristics);

        img_sz+=rnd_sect_vsz;
        if (chrt&(IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_EXECUTE)) code_sz+=rnd_sect_vsz;
        if (chrt&IMAGE_SCN_CNT_INITIALIZED_DATA) initdt_sz+=rnd_sect_vsz;
        if (chrt&IMAGE_SCN_CNT_UNINITIALIZED_DATA) uninitdt_sz+=rnd_sect_vsz;

        i++;
    }
    if (n_del) {
        set_16uint_le(&get_FileHeader(&p_hndl->nt_hdrs).NumberOfSections,
            (UINT16)p_hndl->n_sects);
    }

    /* write recalculated sizes */
    update_pe_sizes(p_hndl, code_sz, initdt_sz, uninitdt_sz, img_sz);

    ret=TRUE;
finish:
    return ret;
}

/* Dump PE headers into the dump output file. Prior to the call the file pointer
   must be set at the beginning of the file.
 */
static BOOL dump_headers_to_file(const dump_pe_hndl_t *p_hndl)
{
    BOOL ret=FALSE, b_ferr=FALSE;

    /* dos header */
    if (b_ferr=(fwrite(&p_hndl->dos_hdr, 1, sizeof(p_hndl->dos_hdr),
        p_hndl->f_out)!=sizeof(p_hndl->dos_hdr))) goto finish;

    /* ms-dos exe stub */
    cpy_ret_t rc = mem2file(
        p_hndl->f_out, p_hndl->mod_base+sizeof(p_hndl->dos_hdr),
        get_32uint_le(&p_hndl->dos_hdr.e_lfanew)-sizeof(p_hndl->dos_hdr));

    if (rc!=cpy_ok) {
        if (rc==cpy_dst_err) b_ferr=TRUE;
        goto finish;
    }

    /* PE signature */
    if (b_ferr=(fwrite(&get_Signature(&p_hndl->nt_hdrs), 1,
        sizeof(get_Signature(&p_hndl->nt_hdrs)), p_hndl->f_out) !=
        sizeof(get_Signature(&p_hndl->nt_hdrs)))) goto finish;

    if (b_ferr=(fwrite(&get_FileHeader(&p_hndl->nt_hdrs), 1,
        sizeof(get_FileHeader(&p_hndl->nt_hdrs)), p_hndl->f_out) !=
        sizeof(get_FileHeader(&p_hndl->nt_hdrs)))) goto finish;

    /* optional header */
    DWORD opt_hdr_sz =
        get_16uint_le(&get_FileHeader(&p_hndl->nt_hdrs).SizeOfOptionalHeader);
    DWORD sz_to_dump = min(
        (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
            sizeof(p_hndl->nt_hdrs.hdr.pe32.OptionalHeader) :
            sizeof(p_hndl->nt_hdrs.hdr.pe64.OptionalHeader)),
        opt_hdr_sz);

    if (b_ferr=(fwrite((p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
            (void*)&p_hndl->nt_hdrs.hdr.pe32.OptionalHeader :
            (void*)&p_hndl->nt_hdrs.hdr.pe64.OptionalHeader),
        1, sz_to_dump, p_hndl->f_out)!=sz_to_dump)) goto finish;

    for (DWORD i=sz_to_dump; i<opt_hdr_sz; i++)
        if (b_ferr=(fputc(0, p_hndl->f_out)==EOF)) goto finish;

    /* some warning */
    ULONG64 pe_mod_base = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
        DEBUG_EXTEND64(get_32uint_le(
            &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.ImageBase)) :
        get_64uint_le(&p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.ImageBase));

    if (pe_mod_base!=p_hndl->mod_base) {
        warn_dbgprintf(
            "Image base mismatch: 0x%p, 0x%p\n", pe_mod_base, p_hndl->mod_base);
    }

    /* sections table */
    if (b_ferr=(fwrite(&p_hndl->sectab[0], 1,
        p_hndl->n_sects*sizeof(p_hndl->sectab[0]),
        p_hndl->f_out)!=p_hndl->n_sects*sizeof(p_hndl->sectab[0]))) goto finish;

    DWORD hdrs_sz = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
        get_32uint_le(&p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.SizeOfHeaders):
        get_32uint_le(&p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.SizeOfHeaders));

    DWORD curr_pos = (DWORD)ftell(p_hndl->f_out);
    if (curr_pos==(DWORD)-1L) { b_ferr=TRUE; goto finish; }

    if (curr_pos>hdrs_sz) {
        err_dbgprintf("Incorrect %s/SizeOfHeaders: 0x%08X\n",
            PROP_SECT_OPTH, hdrs_sz);
        goto finish;
    }

    DWORD save_hdrsp = GetPrivateProfileInt(
        PROP_SECT_DUMP, PROP_DUMP_SAVE_HDR_SPACE, 0, PROP_FILE);

    if (save_hdrsp) {
        rc = mem2file(p_hndl->f_out, p_hndl->mod_base+curr_pos, hdrs_sz-curr_pos);
        if (rc!=cpy_ok) {
            if (rc==cpy_dst_err) b_ferr=TRUE;
            goto finish;
        }
    } else {
        for (DWORD i=curr_pos; i<hdrs_sz; i++)
            if (b_ferr=(fputc(0, p_hndl->f_out)==EOF)) goto finish;
    }

    info_dbgprintf("PE headers have been dumped to the output file\n");
    ret=TRUE;
finish:
    if (b_ferr) err_dbgprintf("Dump file write error\n");
    return ret;
}

/* Dump PE sections content into the dump output file. Prior to the call the
   file pointer must be set at the end of the headers.
 */
static BOOL dump_sections_to_file(const dump_pe_hndl_t *p_hndl)
{
    BOOL ret=FALSE, b_ferr=FALSE;

    for (DWORD i=0; i<p_hndl->n_sects; i++)
    {
        DWORD vsz = get_32uint_le(&p_hndl->sectab[i].Misc.VirtualSize);
        DWORD rva = get_32uint_le(&p_hndl->sectab[i].VirtualAddress);
        DWORD rsz = get_32uint_le(&p_hndl->sectab[i].SizeOfRawData);
        DWORD rptr = get_32uint_le(&p_hndl->sectab[i].PointerToRawData);
        sect_dump_tpy_t dmptpy = p_hndl->sect_dmpcfg[i].tpy;

        if (!rsz) continue;

        /* set output file ptr at the section's raw ptr */
        if (b_ferr=fseek(p_hndl->f_out, 0, SEEK_END)) goto finish;

        DWORD curr_pos = ftell(p_hndl->f_out);
        if (curr_pos==(DWORD)-1L) { b_ferr=TRUE; goto finish; }

        if (rptr<curr_pos) {
            if (b_ferr=fseek(p_hndl->f_out, rptr, SEEK_SET)) goto finish;
        } else {
            for (; curr_pos<rptr; curr_pos++)
                if (b_ferr=(fputc(0, p_hndl->f_out)==EOF)) goto finish;
        }

        cpy_ret_t rc;
        DWORD dump_sz=0;     /* dumped size */

        switch (dmptpy)
        {
        case secdmp_mem:
            if (dump_sz=min(vsz, rsz))
            {
                rc = mem2file(
                    p_hndl->f_out, RVA2ADDR(rva, p_hndl->mod_base), dump_sz);
                if (rc!=cpy_ok)
                {
                    if (get_32uint_le(
                        &p_hndl->sectab[i].Characteristics)&IMAGE_SCN_MEM_DISCARDABLE)
                    {
                        /* if sect is not loaded to memory fill
                           its file space with zeros */
                        dump_sz = 0;
                        if (b_ferr=fseek(p_hndl->f_out, rptr, SEEK_SET)) goto finish;

                        warn_dbgprintf(
                            "Memory access error during dumping discardable "
                            "section %d; filled with zeros\n", i+1);
                    } else {
                        if (rc==cpy_dst_err)
                            b_ferr=TRUE;
                        else
                            err_dbgprintf(
                                "Memory access error during section %d dump\n", i+1);
                        goto finish;
                    }
                }
            }
            break;

        case secdmp_file:
            if (dump_sz=min(p_hndl->sect_dmpcfg[i].dmpfile.fsz, rsz))
            {
                if (fseek(p_hndl->sect_dmpcfg[i].dmpfile.fh, 0, SEEK_SET))
                    rc=cpy_src_err;
                else
                    rc=file2file(
                        p_hndl->f_out, p_hndl->sect_dmpcfg[i].dmpfile.fh, dump_sz);

                if (rc!=cpy_ok) {
                    if (rc==cpy_dst_err)
                        b_ferr=TRUE;
                    else
                        err_dbgprintf("Section %d content file access error\n", i+1);
                    goto finish;
                }
            }
            break;

        /* nothing to do for secdmp_zeros */
        }

        /* fill remaining space (from already dumped space
           to the end of the section's file space) with zeros */
        for (; dump_sz<rsz; dump_sz++)
            if (b_ferr=(fputc(0, p_hndl->f_out)==EOF)) goto finish;
    }

    if (p_hndl->n_sects)
        info_dbgprintf("PE sections have been dumped to the output file\n");
    ret=TRUE;
finish:
    if (b_ferr) err_dbgprintf("Dump file write error\n");
    return ret;
}

/* Update debug directory data */
static BOOL update_debug_dir(const dump_pe_hndl_t *p_hndl)
{
    BOOL ret=FALSE, f_err=FALSE;

    if (!p_hndl->debug_addr) goto no_err;

    DWORD dir_rptr;
    if (!get_raw_ptr(p_hndl, ADDR2RVA(p_hndl->debug_addr, p_hndl->mod_base),
        &dir_rptr, NULL, NULL) || !dir_rptr)
    {
        err_dbgprintf("Debug dir data outside PE sections raw image\n");
        goto err;
    }
    if (f_err=(fseek(p_hndl->f_out, dir_rptr, SEEK_SET) ||
        fwrite(&p_hndl->debug, 1, sizeof(p_hndl->debug), p_hndl->f_out) !=
            sizeof(p_hndl->debug))) goto err;

no_err:
    ret=TRUE;
err:
    if (f_err) err_dbgprintf("File access error: %d\n", ferror(p_hndl->f_out));
    return ret;
}

/* Calculates PE checksum and writes it under 'p_csum'. 'f' is a handle of file
   to calculate, 'org_csum' - original checksum of PE file. The func returns TRUE
   on success.
 */
static BOOL calc_pe_csum(FILE *f, DWORD org_csum, DWORD *p_csum)
{
    BOOL ret=FALSE;

    *p_csum=0;
    if (fseek(f, 0, SEEK_SET)) goto finish;

    DWORD cb;
    ULONG64 sum=0;
    DWORD dwbuf[0x100], len=0;

    do {
        cb = fread(dwbuf, 1, sizeof(dwbuf), f);
        for (DWORD i=0; i<(cb>>2); i++) sum+=get_32uint_le(&dwbuf[i]);
        len += cb;
    } while (cb==sizeof(dwbuf));

    if (!feof(f)) goto finish;

    /* add last remaining word (if present) */
    if (cb&2) sum+=get_16uint_le((UWORD*)&dwbuf[cb>>2]);

    sum -= org_csum;

    /* fold sum to 16 bit long */
    while (sum>>16) sum = (sum>>16) + (sum&0xffff);

    /* if file's length is uneven then add the last byte to the sum */
    if (cb&1) sum = sum + ((UCHAR*)dwbuf)[cb-1];

    *p_csum = (sum&0xffff)+len;

    ret=TRUE;
finish:
    return ret;
}

/* Update PE checksum in the output file */
static BOOL update_pe_csum(const dump_pe_hndl_t *p_hndl)
{
    BOOL ret=FALSE;

    DWORD csum=0;
    if (!calc_pe_csum(p_hndl->f_out, 0, &csum)) {
        warn_dbgprintf("CheckSum calculation error; zero written instead\n");
        goto finish;
    }

    /* zero checksum is already in place, we don't need write it again */
    if (csum)
    {
        DWORD csum_off = get_32uint_le(&p_hndl->dos_hdr.e_lfanew) +
            (UINT8*)(p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
            &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.CheckSum :
            &p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.CheckSum) -
            (UINT8*)&(p_hndl->nt_hdrs.hdr);

        if (!fseek(p_hndl->f_out, csum_off, SEEK_SET) &&
            fwrite(&csum, 1, sizeof(csum), p_hndl->f_out)==sizeof(csum))
        {
            info_dbgprintf("PE checksum written: 0x%08X\n", csum);
            ret=TRUE;
        } else {
            warn_dbgprintf("Error writing PE checksum; zero written instead\n");
        }
    }

finish:
    return ret;
}

/* Extract section 'dmp_sect' (1-based, -1: all sects) into separate file. */
static void extract_sects(dump_pe_hndl_t *p_hndl, DWORD dmp_sect)
{
    if ((dmp_sect>=1 && dmp_sect<=p_hndl->n_sects) || dmp_sect==(DWORD)-1)
    {
        if (!p_hndl->f_out)
        {
            /* we need to re-open & re-read headers of
               the file with bound imports */
            if (!(p_hndl->f_out = fopen(p_hndl->f_out_name, "rb"))) {
                err_dbgprintf(
                    "Can't open dump output file %s\n", p_hndl->f_out_name);
                goto finish;
            }

            ULONG64 sectab_addr;
            if (!read_pe_headers(p_hndl->mod_base, &p_hndl->dos_hdr,
                &p_hndl->nt_hdrs, &sectab_addr, TRUE)) goto finish;

            /* raw pointers may have changed after the bind; re-read them */
            if (p_hndl->n_sects !=
                read_sectab(
                    &p_hndl->nt_hdrs, sectab_addr, p_hndl->sectab, TRUE, TRUE))
            {
                err_dbgprintf("Section tables mismatch\n");
                goto finish;
            }
        }

        /* dump section(s) to separate files */
        DWORD start_sect = 0;
        DWORD end_sect = p_hndl->n_sects;

        if (dmp_sect!=(DWORD)-1) {
            start_sect = dmp_sect-1;
            end_sect = start_sect+1;
        }

        for (UINT i=start_sect; i<end_sect; i++)
        {
            /* open sect file */
            char sect_fname[MAX_PATH+1];
            sprintf(sect_fname, "%s.s%d", p_hndl->f_out_name, i+1);
            sect_fname[MAX_PATH] = 0;

            FILE *f_sect = fopen(sect_fname, "wb");
            if (f_sect)
            {
                DWORD rsz = get_32uint_le(&p_hndl->sectab[i].SizeOfRawData);
                DWORD rptr = get_32uint_le(&p_hndl->sectab[i].PointerToRawData);

                if (rsz) {
                    cpy_ret_t rc;

                    if (!fseek(p_hndl->f_out, rptr, SEEK_SET)) {
                        rc = file2file(f_sect, p_hndl->f_out, rsz);
                    } else {
                        rc = cpy_src_err;
                    }

                    if (rc==cpy_src_err) {
                        err_dbgprintf("Dump file access error\n");
                    } else
                    if (rc==cpy_dst_err) {
                        err_dbgprintf("Extracted section file [%s] write error\n",
                            sect_fname);
                    } else {
                        info_dbgprintf("Section %d extracted\n", i+1);
                    }
                } else {
                    info_dbgprintf("Section %d has empty raw size\n", i+1);;
                }

                fclose(f_sect);
            } else {
                err_dbgprintf(
                    "Can't open extracted section file: %s\n", sect_fname);
            }
        }
    } else
        if (dmp_sect)
            info_dbgprintf("Section number %d out of scope\n", dmp_sect);

finish:
    return;
}

/* exported; see header for details */
BOOL pe_dump(ULONG64 mod_base, DWORD dmp_sect)
{
    BOOL ret=FALSE;
    dump_pe_hndl_t hndl;

    if (!init_dump_pe_hndl(&hndl, mod_base, TRUE)) goto finish;

    /* we need to save original PE crc, since it's cleared later on */
    DWORD org_csum = (hndl.nt_hdrs.pe_tpy==pe_32bit ?
        get_32uint_le(&hndl.nt_hdrs.hdr.pe32.OptionalHeader.CheckSum):
        get_32uint_le(&hndl.nt_hdrs.hdr.pe64.OptionalHeader.CheckSum));

    /* recognize if PE imports are bound */
    BOOL b_bound_imps=FALSE;
    IMAGE_DATA_DIRECTORY *p_dd_bimp;
    if (get_data_dir(&hndl.nt_hdrs,
        IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, &p_dd_bimp, FALSE))
    {
        if (get_32uint_le(&p_dd_bimp->VirtualAddress) &&
            get_32uint_le(&p_dd_bimp->Size)) b_bound_imps=TRUE;
    }

    /* read conf of the dump */
    read_headers_cfg(&hndl);
    read_dirs_cfg(&hndl);
    if (!read_sects_cfg(&hndl)) goto finish;

    /* check all except IAT & IDT dirs
       (since they may be updated by the imports patching) */
    check_refs(&hndl, CHKREF_HEADERS|CHKREF_SECTS|CHKREF_DIRS,
        (1<<IMAGE_DIRECTORY_ENTRY_IMPORT)|(1<<IMAGE_DIRECTORY_ENTRY_IAT));

    if (!dump_headers_to_file(&hndl)) goto finish;
    if (!dump_sections_to_file(&hndl)) goto finish;

    if (!update_debug_dir(&hndl)) {
        warn_dbgprintf("Debug directory update finished with error; "
            "not critical error - continuing...\n");
    }

    if (!patch_imports(&hndl)) goto finish;

    /* after the patch check IAT & IDT dirs */
    check_refs(&hndl, CHKREF_DIRS,
        (UINT32)~((1<<IMAGE_DIRECTORY_ENTRY_IMPORT)|(1<<IMAGE_DIRECTORY_ENTRY_IAT)));

    if (!fix_iat(&hndl)) {
        warn_dbgprintf("IAT table fixing finished with error; "
            "not critical error - continuing...\n");
    }

    if (!fix_rsrc(&hndl)) goto finish;

    char prm_val[20];
    set_val_t sv;

    /* write PE crc */
    if (GetPrivateProfileString(PROP_SECT_DUMP, PROP_DUMP_SET_CRC,
        "", prm_val, sizeof(prm_val), PROP_FILE)<=0) *prm_val=0;

    sv = (set_val_t)get_ht_num(SETVALS_HT, NUM_SETVALS,
        (*prm_val ? prm_val : NULL), set_as_original);

    if (sv==set_always || (sv==set_as_original && org_csum))
        update_pe_csum(&hndl);

    /* bind imports */
    if (GetPrivateProfileString(PROP_SECT_DUMP, PROP_DUMP_BIND_IMPORTS,
        "", prm_val, sizeof(prm_val), PROP_FILE)<=0) *prm_val=0;

    sv = (set_val_t)get_ht_num(SETVALS_HT, NUM_SETVALS,
        (*prm_val ? prm_val : NULL), set_as_original);

    if (sv==set_always || (sv==set_as_original && b_bound_imps))
    {
        /* there is a need to close the output
           file handle before binding the imports */
        fclose(hndl.f_out);
        hndl.f_out=NULL;

        bind_imports(hndl.f_out_name);
    }

    extract_sects(&hndl, dmp_sect);

    ret=TRUE;
finish:
    free_dump_pe_hndl(&hndl);
    if (ret) {
        info_dbgprintf("Dumping process finished with success\n");
    } else {
        err_dbgprintf("Critical error occurred during dumping process\n");
    }
    return ret;
}

/* exported; see header for details */
void suggest_sects_chrt_name(ULONG64 mod_base, DWORD flags)
{
    dump_pe_hndl_t hndl;
    if (!init_dump_pe_hndl(&hndl, mod_base, FALSE)) goto finish;

    if (flags&PROPSC_READ_CONF)
    {
        info_dbgprintf("Reading configuration...\n");
        read_headers_cfg(&hndl);
        read_dirs_cfg(&hndl);
        if (!read_sects_cfg(&hndl)) goto finish;
        dbgprintf("\n");
    }

    DWORD num_dir_ents =
        (hndl.nt_hdrs.pe_tpy==pe_32bit ?
        get_32uint_le(&hndl.nt_hdrs.hdr.pe32.OptionalHeader.NumberOfRvaAndSizes):
        get_32uint_le(&hndl.nt_hdrs.hdr.pe64.OptionalHeader.NumberOfRvaAndSizes));

    DWORD rva, rptr, sect_i;
    DWORD sect_export=(DWORD)-1, sect_idt=(DWORD)-1, sect_iat=(DWORD)-1;
    DWORD sect_rsrc=(DWORD)-1, sect_except=(DWORD)-1, sect_secur=(DWORD)-1;
    DWORD sect_reloc=(DWORD)-1, sect_dbg=(DWORD)-1, sect_arch=(DWORD)-1;
    DWORD sect_tls=(DWORD)-1, sect_tls_dta=(DWORD)-1, sect_lconf=(DWORD)-1;
    DWORD sect_bimp=(DWORD)-1, sect_dimp=(DWORD)-1, sect_comdsc=(DWORD)-1;
    DWORD sect_ep=(DWORD)-1, sect_bascd=(DWORD)-1, sect_basdta=(DWORD)-1;
    DWORD sect_coff_symtab=
        (DWORD)-1, sect_dbg_dta1=(DWORD)-1, sect_dbg_dta2=(DWORD)-1;

    /* go through data directories to recognize containing sections
     */
    ULONG cb;
    for (DWORD i=0; i<num_dir_ents; i++)
    {
        IMAGE_DATA_DIRECTORY *p_dd =
            (IMAGE_DATA_DIRECTORY*)(hndl.nt_hdrs.pe_tpy==pe_32bit ?
            &hndl.nt_hdrs.hdr.pe32.OptionalHeader.DataDirectory[i]:
            &hndl.nt_hdrs.hdr.pe64.OptionalHeader.DataDirectory[i]);

        rva = get_32uint_le(&p_dd->VirtualAddress);
        if (!get_32uint_le(&p_dd->Size) || !rva) continue;

        if (i==IMAGE_DIRECTORY_ENTRY_SECURITY) {
            /* VirtualAddress is a raw pointer */
            if (!get_rptr_info(
                hndl.sectab, hndl.n_sects, rva, &sect_i, NULL, NULL))
                    continue;
        } else {
            if (!get_rva_info(
                hndl.sectab, hndl.n_sects, rva, &sect_i, NULL, NULL, NULL))
                    continue;
        }

        switch (i)
        {
        case IMAGE_DIRECTORY_ENTRY_EXPORT:
            sect_export=sect_i; break;
        case IMAGE_DIRECTORY_ENTRY_IMPORT:
            sect_idt=sect_i; break;
        case IMAGE_DIRECTORY_ENTRY_IAT:
            sect_iat=sect_i; break;
        case IMAGE_DIRECTORY_ENTRY_RESOURCE:
            sect_rsrc=sect_i; break;
        case IMAGE_DIRECTORY_ENTRY_EXCEPTION:
            sect_except=sect_i; break;
        case IMAGE_DIRECTORY_ENTRY_SECURITY:
            sect_secur=sect_i; break;
        case IMAGE_DIRECTORY_ENTRY_BASERELOC:
            sect_reloc=sect_i; break;
        case IMAGE_DIRECTORY_ENTRY_DEBUG:
          {
            sect_dbg=sect_i;

            /* recognize debug data section */
            IMAGE_DEBUG_DIRECTORY debug = hndl.debug;
            if (!hndl.debug_addr) {
                if (!(read_memory(RVA2ADDR(rva, mod_base),
                    &debug, sizeof(debug), &cb) && cb==sizeof(debug))) continue;
            }

            DWORD dta_rva = get_32uint_le(&debug.AddressOfRawData);
            if (dta_rva && get_rva_info(
                hndl.sectab, hndl.n_sects, dta_rva, &sect_i, NULL, NULL, NULL))
                    sect_dbg_dta1=sect_i;

            DWORD dta_rptr = get_32uint_le(&debug.PointerToRawData);
            if (dta_rptr && get_rptr_info(
                hndl.sectab, hndl.n_sects, dta_rptr, &sect_i, NULL, NULL))
                    sect_dbg_dta2=sect_i;
            break;
          }
        case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:
            sect_arch=sect_i; break;
        case IMAGE_DIRECTORY_ENTRY_TLS:
          {
            sect_tls=sect_i;

            /* recognize TLS data section */
            DWORD tls_rva;
            if (hndl.nt_hdrs.pe_tpy==pe_32bit) {
                /* 32-bit TLS */
                IMAGE_TLS_DIRECTORY32 tls;
                if (!(read_memory(RVA2ADDR(rva, mod_base), &tls, sizeof(tls), &cb)
                    && cb==sizeof(tls))) continue;

                tls_rva = ADDR2RVA(DEBUG_EXTEND64(
                    get_32uint_le(&tls.StartAddressOfRawData)), mod_base);
            } else {
                /* 64-bit TLS */
                IMAGE_TLS_DIRECTORY64 tls;
                if (!(read_memory(RVA2ADDR(rva, mod_base), &tls, sizeof(tls), &cb)
                    && cb==sizeof(tls))) continue;

                tls_rva = ADDR2RVA(get_64uint_le(
                    &tls.StartAddressOfRawData), mod_base);
            }
            if (tls_rva && get_rva_info(
                hndl.sectab, hndl.n_sects, tls_rva, &sect_i, NULL, NULL, NULL))
                    sect_tls_dta=sect_i;
            break;
          }
        case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
            sect_lconf=sect_i; break;
        case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
            sect_bimp=sect_i; break;
        case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
            sect_dimp=sect_i; break;
        case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
            sect_comdsc=sect_i; break;
        }
    }

    rva = (hndl.nt_hdrs.pe_tpy==pe_32bit ?
        get_32uint_le(&hndl.nt_hdrs.hdr.pe32.OptionalHeader.AddressOfEntryPoint):
        get_32uint_le(&hndl.nt_hdrs.hdr.pe64.OptionalHeader.AddressOfEntryPoint));
    if (rva && get_rva_info(
        hndl.sectab, hndl.n_sects, rva, &sect_i, NULL, NULL, NULL))
            sect_ep=sect_i;

    rva = (hndl.nt_hdrs.pe_tpy==pe_32bit ?
        get_32uint_le(&hndl.nt_hdrs.hdr.pe32.OptionalHeader.BaseOfCode):
        get_32uint_le(&hndl.nt_hdrs.hdr.pe64.OptionalHeader.BaseOfCode));
    if (rva && get_rva_info(
        hndl.sectab, hndl.n_sects, rva, &sect_i, NULL, NULL, NULL))
            sect_bascd=sect_i;

    if (hndl.nt_hdrs.pe_tpy==pe_32bit) {
        rva = get_32uint_le(&hndl.nt_hdrs.hdr.pe32.OptionalHeader.BaseOfData);
        if (rva && get_rva_info(
            hndl.sectab, hndl.n_sects, rva, &sect_i, NULL, NULL, NULL))
                sect_basdta=sect_i;
    }

    rptr = get_32uint_le(&get_FileHeader(&hndl.nt_hdrs).PointerToSymbolTable);
    if (rptr && get_rptr_info(
        hndl.sectab, hndl.n_sects, rptr, &sect_i, NULL, NULL))
            sect_coff_symtab=sect_i;

    /* go through all sections to recognize type of content and print it
     */

    /* possible data sects counter */
    UINT sect_dta_n=0;

    dbgprintf("[%s]\n", PROP_SECT_SECTS);

    for (DWORD i=0; i<hndl.n_sects; i++)
    {
        /* sections content bitmap */
        DWORD sect_cont=0;

        if (sect_export==i) sect_cont|=SCONT_EXPORT;
        if (sect_idt==i || sect_iat==i) sect_cont|=SCONT_IMPORT;
        if (sect_rsrc==i) sect_cont|=SCONT_RSRC;
        if (sect_except==i) sect_cont|=SCONT_EXCEPTION;
        if (sect_secur==i) sect_cont|=SCONT_SECURITY;
        if (sect_reloc==i) sect_cont|=SCONT_RELOC;
        if (sect_dbg==i) sect_cont|=SCONT_DEBUG;
        if (sect_dbg_dta1==i || sect_dbg_dta2==i) sect_cont|=SCONT_DEBUG_DTA;
        if (sect_arch==i) sect_cont|=SCONT_ARCH;
        if (sect_tls==i) sect_cont|=SCONT_TLS;
        if (sect_tls_dta==i) sect_cont|=SCONT_TLS_DTA;
        if (sect_lconf==i) sect_cont|=SCONT_LOAD_CFG;
        if (sect_bimp==i) sect_cont|=SCONT_BND_IMPORT;
        if (sect_dimp==i) sect_cont|=SCONT_DELAY_IMPORT;
        if (sect_comdsc==i) sect_cont|=SCONT_COM_DESC;
        if (sect_ep==i || sect_bascd==i) sect_cont|=SCONT_CODE;
        if (sect_basdta==i) sect_cont|=SCONT_DATA;
        if (sect_coff_symtab==i) sect_cont|=SCONT_COFF_SYMTAB;

        /* check COFF relocs and line nums */
        for (DWORD j=0; j<hndl.n_sects; j++)
        {
            rptr = get_32uint_le(&hndl.sectab[j].PointerToRelocations);
            if (rptr && get_rptr_info(
                hndl.sectab, hndl.n_sects, rptr, &sect_i, NULL, NULL))
            {
                if (sect_i==i) sect_cont|=SCONT_COFF_RELOC;
            }

            rptr = get_32uint_le(&hndl.sectab[j].PointerToLinenumbers);
            if (rptr && get_rptr_info(
                hndl.sectab, hndl.n_sects, rptr, &sect_i, NULL, NULL))
            {
                if (sect_i==i) sect_cont|=SCONT_COFF_LINE_NUM;
            }
        }

        /* print results
         */
        DWORD chrt;
        const char *pc_name;
        char name[IMAGE_SIZEOF_SHORT_NAME+1];

        if (!sect_cont || sect_cont==SCONT_DATA)
        {
            /* r/w data section */
            if (!get_32uint_le(&hndl.sectab[i].SizeOfRawData))
            {
                /* ".bss" uninit section */
                pc_name = ".bss";
                chrt = IMAGE_SCN_CNT_UNINITIALIZED_DATA|IMAGE_SCN_MEM_READ|
                    IMAGE_SCN_MEM_WRITE;
            } else {
                if (!sect_dta_n) {
                    /* 1st sect of unspec. type is usually r/w initialized ".data" */
                    pc_name = ".data";
                    chrt = IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ|
                        IMAGE_SCN_MEM_WRITE;
                } else {
                    /* unrecognised sect - remain current spec. */
                    strncpy(name, (char*)&hndl.sectab[i].Name[0], sizeof(name)-1);
                    name[sizeof(name)-1] = 0;
                    pc_name = name;

                    chrt = get_32uint_le(&hndl.sectab[i].Characteristics);
                }
                sect_dta_n++;
            }
        } else
        {
            /* recognize type basing on its pattern */
            UINT j;
            for (j=0;
                 j<sizeof(sects_pattrn)/sizeof(sects_pattrn[0]);
                 j++)
            {
                /* section content must be included in max content to match */
                if ((sect_cont&sects_pattrn[j].cont)==sect_cont) {
                    pc_name = sects_pattrn[j].pc_name;
                    chrt = sects_pattrn[j].chrt;
                    break;
                }
            }

            if (j>=sizeof(sects_pattrn)/sizeof(sects_pattrn[0])) {
                /* unrecognised sect - remain current spec. */
                strncpy(name, (char*)&hndl.sectab[i].Name[0], sizeof(name)-1);
                name[sizeof(name)-1] = 0;
                pc_name = name;

                chrt = get_32uint_le(&hndl.sectab[i].Characteristics);
            }
        }

        dbgprintf("%d.%s = %s\n", i+1, PROP_SECTS_NAME, pc_name);
        dbgprintf("%d.%s = 0x%08X", i+1, PROP_SECTS_CHARACTER, chrt);
        print_flags(SECCHRVALS_HT, NUM_SECCHRVALS, chrt, 32);
    }

finish:
    free_dump_pe_hndl(&hndl);
    return;
}
