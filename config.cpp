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

static char prop_file[MAX_PATH+1];
const char *PROP_FILE = &prop_file[0];

static char home_path[MAX_PATH+1];
const char *HOME_PATH = &home_path[0];

/*
    conf section & params names
 */
const char *PROP_SECT_OPTH = "optional_header";
const char *PROP_OPTH_ENTRY_POINT = "AddressOfEntryPoint";
const char *PROP_OPTH_BASE_CODE = "BaseOfCode";
const char *PROP_OPTH_BASE_DATA = "BaseOfData";

const char *PROP_SECT_DIRS = "directories";
const char *PROP_DIRS_EXP_RVA = "ExportTab.rva";
const char *PROP_DIRS_EXP_SZ = "ExportTab.size";
const char *PROP_DIRS_IDT_RVA = "ImportTab.rva";
const char *PROP_DIRS_IDT_SZ = "ImportTab.size";
const char *PROP_DIRS_RSRC_RVA = "ResourceTab.rva";
const char *PROP_DIRS_RSRC_SZ = "ResourceTab.size";
const char *PROP_DIRS_EXPT_RVA = "ExceptionTab.rva";
const char *PROP_DIRS_EXPT_SZ = "ExceptionTab.size";
const char *PROP_DIRS_CERT_RVA = "CertificateTab.rva";
const char *PROP_DIRS_CERT_SZ = "CertificateTab.szie";
const char *PROP_DIRS_RELOC_RVA = "BaseRelocTab.rva";
const char *PROP_DIRS_RELOC_SZ = "BaseRelocTab.size";
const char *PROP_DIRS_DBG_RVA = "Debug.rva";
const char *PROP_DIRS_DBG_SZ = "Debug.size";
const char *PROP_DIRS_ARCH_RVA = "Architecture.rva";
const char *PROP_DIRS_ARCH_SZ = "Architecture.size";
const char *PROP_DIRS_GPTR_RVA = "GlobalPtr.rva";
const char *PROP_DIRS_GPTR_SZ = "GlobalPtr.size";
const char *PROP_DIRS_TLS_RVA = "TLSTab.rva";
const char *PROP_DIRS_TLS_SZ = "TLSTab.size";
const char *PROP_DIRS_CFG_RVA = "LoadConfigTab.rva";
const char *PROP_DIRS_CFG_SZ = "LoadConfigTab.size";
const char *PROP_DIRS_BOUND_RVA = "BoundImportTab.rva";
const char *PROP_DIRS_BOUND_SZ = "BoundImportTab.size";
const char *PROP_DIRS_IAT_RVA = "IAT.rva";
const char *PROP_DIRS_IAT_SZ = "IAT.size";
const char *PROP_DIRS_DELAY_RVA = "DelayImportDesc.rva";
const char *PROP_DIRS_DELAY_SZ = "DelayImportDesc.size";
const char *PROP_DIRS_CLR_RVA = "CLRRuntimeHeader.rva";
const char *PROP_DIRS_CLR_SZ = "CLRRuntimeHeader.size";

const char *PROP_SECT_SECTS = "sections";
const char *PROP_SECTS_DEL_TRAILING_SECS = "RemoveTrailingSections";
const char *PROP_SECTS_NAME = "Name";
const char *PROP_SECTS_CHARACTER = "Characteristics";
const char *PROP_SECTS_VSZ = "VirtualSize";
const char *PROP_SECTS_RVA = "VirtualAddress";
const char *PROP_SECTS_RSZ = "SizeOfRawData";
const char *PROP_SECTS_DMPCONT = "DumpedContent";

const char *PROP_SECT_IMPFIX = "imports_fix";
const char *PROP_IMPFIX_NO_PADD_NAMES = "NoPaddNames";
const char *PROP_IMPFIX_NO_ILTS = "NoILTs";
const char *PROP_IMPFIX_HN_TAB_RVA = "FollowIDT.HintNameTab.rva";
const char *PROP_IMPFIX_NAME_TAB_RVA = "FollowIDT.NameTab.rva";

const char *PROP_SECT_DUMP = "dump_pe";
const char *PROP_DUMP_OUTPUT = "OutFile";
const char *PROP_DUMP_SET_CRC = "SetCrc";
const char *PROP_DUMP_SAVE_HDR_SPACE = "SaveHeaderSpace";
const char *PROP_DUMP_BIND_IMPORTS = "BindImports";

const char *PROP_SECT_CONFLSPEC = "mod_conflicts_reslv";

const char *PROP_SECT_IMPSPEC = "imports";
const char *PROP_IMPSPEC_IAT_RVA = "iat_rva";

const char *PROP_SECT_RSRCFIX = "rsrc_fix";
const char *PROP_RSRCFIX_RECOVER = "RecoverRsrc";
const char *PROP_RSRCFIX_RSRC_RVA = PROP_DIRS_RSRC_RVA;
const char *PROP_RSRCFIX_PADD = "PaddRsrc";
const char *PROP_RSRCFIX_TMPFILE = "TmpRsrcFile";
const char *PROP_RSRCFIX_KEEP_TMPFILE = "KeepTmpRsrcFile";

/*
    special param values & default values
 */
const char *OUT_DUMP_DEF_FILE = "dump.out";
const char *OUT_TMP_RSRC_DEF_FILE = "$rsrc.tmp";    /* in the tmp dir */

const char *IDT_AFTER_IAT = "after_iat";
const char *RSZ_AS_VSZ = "vsize";
const char *RSZ_AUTO = "auto";

const char *DMPCONT_MEM = "memory";
const char *DMPCONT_ZEROS = "zeros";
const char *DMPCONT_FILE = "file:";


/* "set" values hash tab */
static const str_num_t setvals_ht[] =
{
    {"no", set_no},
    {"as_original", set_as_original},
    {"always", set_always}
};
const size_t NUM_SETVALS = sizeof(setvals_ht)/sizeof(setvals_ht[0]);
const str_num_t *SETVALS_HT = &setvals_ht[0];

/* "rsrc recovery" values hash tab */
static const str_num_t rsrcrvvals_ht[] =
{
    {"no", rsrcrv_no},
    {"yes", rsrcrv_yes},
    {"detect", rsrcrv_detect},
};
const size_t NUM_RSRCRVVALS = sizeof(rsrcrvvals_ht)/sizeof(rsrcrvvals_ht[0]);
const str_num_t *RSRCRVVALS_HT = &rsrcrvvals_ht[0];

/* "rsrc padding" values hash tab */
static const str_num_t paddvals_ht[] =
{
    {"no", padd_no},
    {"word", padd_w},
    {"dword", padd_dw},
    {"auto", padd_auto},
};
const size_t NUM_PADDVALS = sizeof(paddvals_ht)/sizeof(paddvals_ht[0]);
const str_num_t *PADDVALS_HT = &paddvals_ht[0];

/* "section characteristics" values hash tab */
static const str_num_t secchrvals_ht[] =
{
    {"no_pad", IMAGE_SCN_TYPE_NO_PAD},
    {"code", IMAGE_SCN_CNT_CODE},
    {"init_data", IMAGE_SCN_CNT_INITIALIZED_DATA},
    {"uninit_data", IMAGE_SCN_CNT_UNINITIALIZED_DATA},
    {"lnk_other", IMAGE_SCN_LNK_OTHER},
    {"lnk_info", IMAGE_SCN_LNK_INFO},
    {"lnk_remove", IMAGE_SCN_LNK_REMOVE},
    {"lnk_comdat", IMAGE_SCN_LNK_COMDAT},
    {"no_defer_spec_exc", IMAGE_SCN_NO_DEFER_SPEC_EXC},
    {"gp_refer", IMAGE_SCN_GPREL},
    {"purgable", IMAGE_SCN_MEM_PURGEABLE},
    {"locked", IMAGE_SCN_MEM_LOCKED},
    {"preload", IMAGE_SCN_MEM_PRELOAD},
    {"algn_bit1", IMAGE_SCN_ALIGN_1BYTES},
    {"algn_bit2", IMAGE_SCN_ALIGN_2BYTES},
    {"algn_bit3", IMAGE_SCN_ALIGN_8BYTES},
    {"algn_bit4", IMAGE_SCN_ALIGN_128BYTES},
    {"lnk_nreloc_ovfl", IMAGE_SCN_LNK_NRELOC_OVFL},
    {"discardable", IMAGE_SCN_MEM_DISCARDABLE},
    {"not_cached", IMAGE_SCN_MEM_NOT_CACHED},
    {"not_paged", IMAGE_SCN_MEM_NOT_PAGED},
    {"shared", IMAGE_SCN_MEM_SHARED},
    {"exec", IMAGE_SCN_MEM_EXECUTE},
    {"read", IMAGE_SCN_MEM_READ},
    {"write", IMAGE_SCN_MEM_WRITE}
};
const size_t NUM_SECCHRVALS = sizeof(secchrvals_ht)/sizeof(secchrvals_ht[0]);
const str_num_t *SECCHRVALS_HT = &secchrvals_ht[0];

/* "file header characteristics" values hash tab */
static const str_num_t flchrvals_ht[] =
{
    {"reloc_strip", IMAGE_FILE_RELOCS_STRIPPED},
    {"exe", IMAGE_FILE_EXECUTABLE_IMAGE},
    {"lines_strip", IMAGE_FILE_LINE_NUMS_STRIPPED},
    {"syms_strip", IMAGE_FILE_LOCAL_SYMS_STRIPPED},
    {"aggr_ws_trim", IMAGE_FILE_AGGRESIVE_WS_TRIM},
    {"big_addr_aware", IMAGE_FILE_LARGE_ADDRESS_AWARE},
    {"little_end", IMAGE_FILE_BYTES_REVERSED_LO},
    {"32_bit", IMAGE_FILE_32BIT_MACHINE},
    {"dbg_strip", IMAGE_FILE_DEBUG_STRIPPED},
    {"remov_media", IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP},
    {"net_media", IMAGE_FILE_NET_RUN_FROM_SWAP},
    {"system", IMAGE_FILE_SYSTEM},
    {"dll", IMAGE_FILE_DLL},
    {"uniproc", IMAGE_FILE_UP_SYSTEM_ONLY},
    {"big_end", IMAGE_FILE_BYTES_REVERSED_HI}
};
const size_t NUM_FLCHRVALS = sizeof(flchrvals_ht)/sizeof(flchrvals_ht[0]);
const str_num_t *FLCHRVALS_HT = &flchrvals_ht[0];

/* "dll characteristics" values hash tab */
static const str_num_t dllchrvals_ht[] =
{
    {"dyn_base", IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE},
    {"force_integr", IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY},
    {"nx_compat", IMAGE_DLLCHARACTERISTICS_NX_COMPAT},
    {"no_isolation", IMAGE_DLLCHARACTERISTICS_NO_ISOLATION},
    {"no_seh", IMAGE_DLLCHARACTERISTICS_NO_SEH},
    {"no_bind", IMAGE_DLLCHARACTERISTICS_NO_BIND},
    {"wdm", IMAGE_DLLCHARACTERISTICS_WDM_DRIVER},
    {"term_aware", IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE}
};
const size_t NUM_DLLCHRVALS = sizeof(dllchrvals_ht)/sizeof(dllchrvals_ht[0]);
const str_num_t *DLLCHRVALS_HT = &dllchrvals_ht[0];

/* "memory info" values hash tab */
static const str_num_t meminfovals_ht[] =
{
    {"PAGE_NOACCESS", PAGE_NOACCESS},
    {"PAGE_READONLY", PAGE_READONLY},
    {"PAGE_READWRITE", PAGE_READWRITE},
    {"PAGE_WRITECOPY", PAGE_WRITECOPY},
    {"PAGE_EXECUTE", PAGE_EXECUTE},
    {"PAGE_EXECUTE_READ", PAGE_EXECUTE_READ},
    {"PAGE_EXECUTE_READWRITE", PAGE_EXECUTE_READWRITE},
    {"PAGE_EXECUTE_WRITECOPY", PAGE_EXECUTE_WRITECOPY},
    {"PAGE_GUARD", PAGE_GUARD},
    {"PAGE_NOCACHE", PAGE_NOCACHE},
    {"PAGE_WRITECOMBINE", PAGE_WRITECOMBINE},
    {"MEM_COMMIT", MEM_COMMIT},
    {"MEM_RESERVE", MEM_RESERVE},
    {"MEM_DECOMMIT", MEM_DECOMMIT},
    {"MEM_RELEASE", MEM_RELEASE},
    {"MEM_FREE", MEM_FREE},
    {"MEM_PRIVATE", MEM_PRIVATE},
    {"MEM_MAPPED", MEM_MAPPED},
    {"MEM_RESET", MEM_RESET},
    {"MEM_TOP_DOWN", MEM_TOP_DOWN},
    {"MEM_WRITE_WATCH", MEM_WRITE_WATCH},
    {"MEM_PHYSICAL", MEM_PHYSICAL},
    {"MEM_ROTATE", MEM_ROTATE},
    {"MEM_LARGE_PAGES", MEM_LARGE_PAGES},
    {"MEM_4MB_PAGES", MEM_4MB_PAGES},
    {"SEC_IMAGE", SEC_IMAGE},
    {"SEC_PROTECTED_IMAGE", SEC_PROTECTED_IMAGE},
    {"SEC_RESERVE", SEC_RESERVE},
    {"SEC_COMMIT", SEC_COMMIT},
    {"SEC_NOCACHE", SEC_NOCACHE},
    {"SEC_WRITECOMBINE", SEC_WRITECOMBINE}
};
const size_t NUM_MEMINFOVALS = sizeof(meminfovals_ht)/sizeof(meminfovals_ht[0]);
const str_num_t *MEMINFOVALS_HT = &meminfovals_ht[0];


/* exported; see header for details */
DWORD get_ht_num(
    const str_num_t *ht, size_t ht_sz, const char *str, DWORD def_val)
{
    DWORD ret = def_val;

    if (str) {
        for (size_t i=0; i<ht_sz; i++) {
            if (!strcmpi(ht[i].str, str)) { ret = ht[i].num; break; }
        }
    }
    return ret;
}

/* exported; see header for details */
const char *get_ht_str(
    const str_num_t *ht, size_t ht_sz, DWORD num, const char *def_val)
{
    const char *ret = def_val;

    for (size_t i=0; i<ht_sz; i++) {
        if (ht[i].num == num) { ret = ht[i].str; break; }
    }
    return ret;
}

/* exported; see header for details */
void print_flags(const str_num_t *ht, size_t ht_sz, DWORD flags, UINT bits)
{
    if (flags) {
        char sep=' ';

        dbgprintf("   ;");
        for (DWORD bt=1, i=0; i<bits; bt=bt<<1, i++) {
            if (flags & bt) {
                const char *flg_str = get_ht_str(ht, ht_sz, bt, NULL);
                if (flg_str) { dbgprintf("%c%s", sep, flg_str); sep='|'; }
            }
        }
    }
    dbgprintf("\n");
}

/* exported; see header for details */
DWORD parse_flags(const str_num_t *ht, size_t ht_sz, char *pc_flags)
{
    DWORD flags=0;

    for (; *pc_flags; pc_flags++)
    {
        if (isspace(*pc_flags) || *pc_flags=='|') continue;

        char *pc_end=strchr(pc_flags, '|'), *pc_cont=NULL;
        if (!pc_end) pc_end=pc_flags+strlen(pc_flags);
        else pc_cont=pc_end;

        for (pc_end--; pc_flags<pc_end && isspace(*pc_end); pc_end--);
        *(++pc_end)=0;

        DWORD flag=get_ht_num(ht, ht_sz, pc_flags, 0);
        if (!flag) flag=strtoul(pc_flags, NULL, 0);

        flags|=flag;

        if (pc_cont) pc_flags=pc_cont;
        else break;
    }
    return flags;
}

/* exported; see header for details */
void init_config(HINSTANCE hinstDLL)
{
    char dll_fname[MAX_PATH+1];

    /* extract home dir */
    if (GetModuleFileName(hinstDLL, dll_fname, sizeof(dll_fname)) > 0)
    {
        *(name_from_path(dll_fname))=0;
        strcpy(home_path, dll_fname);
    } else
        *home_path=0;

    _snprintf(prop_file, sizeof(prop_file), "%s%s", home_path, "dumpext.conf");
    prop_file[sizeof(prop_file)-1] = 0;
}

/* exported; see header for details */
void set_prop_file(const char* pc_prop_file)
{
    strncpy(prop_file, pc_prop_file, sizeof(prop_file));
    prop_file[sizeof(prop_file)-1]=0;
}
