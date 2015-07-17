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

#include <imagehlp.h>
#include <errno.h>

/* max number of symbols in a dll with an identical addr */
#define MAX_SYNONS   20U

/* max number of forwarders' modules taken into account
   during resolving an owning module of its IAT table */
#define MAX_FRWRDS   32U

#define IDTSPEC_NO_PADD_NAMES   0x01U
#define IDTSPEC_NO_ILTS         0x02U

typedef struct _imp_proc_desc_t
{
    /* ordinal of a proc (index in the export addr table;
       "base-ordinal" based); required to be set if proc has no name */
    DWORD ord;

    /* hint of a proc (index in name/hint table; 0-based); if a proc
       has no name (only an ordinal) hint is set to (DWORD)-1 */
    DWORD hint;

    /* number of duplicates of the proc (set only
       for the 1st dup in the module's list of procs) */
    DWORD dups;

    /* next proc in the chain */
    _imp_proc_desc_t *next;

    /* proc name (NULL term; rounded to even bytes by padding zero);
       if a proc has no name (only ordinal) this string is set to "" */
    char name[1];
} imp_proc_desc_t;

typedef struct _imp_mod_desc_t
{
    /* imported module's base (may be NULL for imports read
       form the conf file and not able to be resolved) */
    ULONG64 mod_base;

    /* module's IAT table address */
    ULONG64 iat_addr;

    /* num of proc descs in the list */
    DWORD n_procs;

    /* 1st imported proc desc of the list */
    imp_proc_desc_t *proc;

    /* number of duplicates of the module (set only
       for the 1st dup in the list of importing mods) */
    DWORD dups;

    /* size of module's Hint/Name Table (in bytes) */
    DWORD hnt_sz;

    /* size of module's Hint/Name Table (in bytes) w/o even rounded proc names */
    DWORD hnt_nrnd_sz;

    /* next module in the chain  */
    _imp_mod_desc_t *next;

    /* module name (NULL term; rounded to even bytes by padding zero) */
    char name[1];
} imp_mod_desc_t;

/* selected module's export directory's fields */
typedef struct _mod_exp_dir_t
{
    /* module's base addr */
    ULONG64 mod_base;

    /* exp dir data addr & size */
    ULONG64 exp_dd_addr;
    DWORD exp_dd_sz;

    /* exp dir data content */
    DWORD ord_base;         /* ordinal's base */
    DWORD n_faddrs;         /* number of functions in EAT */
    DWORD n_fnames;         /* number of exported names */
    ULONG64 mod_name_addr;  /* module's name address */
    ULONG64 faddrs_addr;    /* address of EAT */
    ULONG64 fnames_addr;    /* address of names table */
    ULONG64 fords_addr;     /* address of ordinals table */
} mod_exp_dir_t;

/* struct of internal handle for imports scan */
typedef struct _scan_imps_hndl_t
{
    /* module's base */
    ULONG64 mod_base;

    /* module's headers */
    IMAGE_DOS_HEADER dos_hdr;
    image_nt_headers_t nt_hdrs;

    /* sections table */
    DWORD n_sects;
    IMAGE_SECTION_HEADER sectab[MAX_SECTIONS];

    /* TRUE if 32bit target emulated on Wow64 platform */
    BOOL wow64_emul;

    /* flag indicating end of current module's
       imports and a need to create a new one */
    BOOL crt_new_list;

    DWORD n_mods;                   /* number of modules in the imp_mods list */
    imp_mod_desc_t *p_imp_mods;     /* pointer to the head of mod desc's struct */
    imp_mod_desc_t *p_last_mod;     /* lastly added mod desc */
    imp_proc_desc_t *p_last_proc;   /* lastly added proc desc */

    mod_exp_dir_t ed_reslv;         /* cache of exp dir - proc resolving */
    mod_exp_dir_t ed_frwrd;         /* cache of exp dir - forwards resolving */
} scan_imps_hndl_t;

/* delay load description struct */
typedef struct _img_delay_descr_t
{
    DWORD attrs;          /* attributes */
    DWORD rvaDLLName;     /* RVA to dll name */
    DWORD rvaHmod;        /* RVA of module handle */
    DWORD rvaIAT;         /* RVA of the IAT */
    DWORD rvaILT;         /* RVA of the ILT */
    DWORD rvaBoundIAT;    /* RVA of the optional bound IAT */
    DWORD rvaUnloadIAT;   /* RVA of optional copy of original IAT */
    DWORD dwTimeStamp;    /* 0 if not bound, otherwise
                             date/time stamp of DLL bound to (Old BIND) */
} img_delay_descr_t;

/* Delay Load Attributes */
enum delay_imp_attr
{
    /* RVAs are used instead of pointers */
    dlattr_rva = 0x1
};

/* Read the export directory and write the data into the structure pointed by
   'p_ed'. The func requires p_ed->mod_base to be set to the base of the module
   whose export dir need to be read. If 'b_logs' is TRUE print error info. Return
   TRUE for success, FALSE otherwise
 */
static BOOL get_mod_exp_dir(mod_exp_dir_t *p_ed, BOOL b_logs)
{
    BOOL ret=FALSE;

    IMAGE_DOS_HEADER dos_hdr;
    image_nt_headers_t nt_hdrs;

    /* read PE header and the export directory */
    if (!read_pe_headers(p_ed->mod_base, &dos_hdr, &nt_hdrs, NULL, b_logs))
        goto finish;

    IMAGE_DATA_DIRECTORY *p_dd_exp;
    if (!get_data_dir(&nt_hdrs, IMAGE_DIRECTORY_ENTRY_EXPORT, &p_dd_exp, b_logs))
        goto finish;

    DWORD exp_dd_rva = get_32uint_le(&p_dd_exp->VirtualAddress);

    p_ed->exp_dd_addr = RVA2ADDR(exp_dd_rva, p_ed->mod_base);
    p_ed->exp_dd_sz = get_32uint_le(&p_dd_exp->Size);

    if (!exp_dd_rva || !p_ed->exp_dd_sz) {
        if (b_logs)
            err_dbgprintf(
                "No export directory for a module with the base addr: 0x%p\n",
                p_ed->mod_base);
        goto finish;
    }

    ULONG cb;
    IMAGE_EXPORT_DIRECTORY exp_dir;

    /* retrieve export table info */
    if (!(read_memory(p_ed->exp_dd_addr,
        &exp_dir, sizeof(exp_dir), &cb) && cb==sizeof(exp_dir))) goto finish;

    p_ed->ord_base = get_32uint_le(&exp_dir.Base);
    p_ed->n_faddrs = get_32uint_le(&exp_dir.NumberOfFunctions);
    p_ed->n_fnames = get_32uint_le(&exp_dir.NumberOfNames);
    p_ed->mod_name_addr =
        RVA2ADDR(get_32uint_le(&exp_dir.Name), p_ed->mod_base);
    p_ed->faddrs_addr =
        RVA2ADDR(get_32uint_le(&exp_dir.AddressOfFunctions), p_ed->mod_base);
    p_ed->fnames_addr =
        RVA2ADDR(get_32uint_le(&exp_dir.AddressOfNames), p_ed->mod_base);
    p_ed->fords_addr =
        RVA2ADDR(get_32uint_le(&exp_dir.AddressOfNameOrdinals), p_ed->mod_base);

    ret=TRUE;
finish:
    return ret;
}

/* Search for the proc name pointed by 'pc_proc_name' in the exported table of
   names. Optimized method basing on a lexical order of names in the exporting
   table. If the name is found the func returns TRUE and proc's hint & ordinal
   (zero-based) are returned under 'p_hint' and 'p_ord'.
 */
static BOOL get_name_hint_ord(const mod_exp_dir_t *p_ed,
    const char *pc_proc_name, DWORD *p_hint, DWORD *p_ord)
{
    ULONG cb;
    BOOL ret=FALSE, found=FALSE;
    BOOL loop_finish=FALSE;

    if (!p_ed->n_fnames) goto finish;

    for (DWORD h_min=0, h_max=p_ed->n_fnames-1, h_mid; !loop_finish;)
    {
        if (h_min==h_max) loop_finish=TRUE;

        /* read proc name address in the middle of the searching range */
        h_mid = (h_min+h_max)/2;

        DWORD proc_name_rva;
        if (!(read_memory(p_ed->fnames_addr + h_mid*sizeof(proc_name_rva),
            &proc_name_rva, sizeof(proc_name_rva), &cb) &&
            cb==sizeof(proc_name_rva))) goto finish;

        ULONG64 proc_name_addr =
            RVA2ADDR(get_32uint_le(&proc_name_rva), p_ed->mod_base);

        int cmp_res = string_cmp_lt(pc_proc_name, proc_name_addr);
        if (!cmp_res) {
            *p_hint = h_mid;
            found = TRUE;
            break;
        } else
        if (cmp_res>0) {
            h_min = (h_min!=h_mid ? h_mid : h_max);
        } else {
            if (h_min!=h_mid) h_max=h_mid;
            else break;
        }
    }

    if (found) {
        WORD ord;
        if (!(read_memory(p_ed->fords_addr + *p_hint*sizeof(ord),
            &ord, sizeof(ord), &cb) && cb==sizeof(ord))) goto finish;

        *p_ord = get_16uint_le(&ord);
    }

    ret=TRUE;
finish:
    return ret;
}

/* Count how many modules from the 'p_mods' list ('n_mods' long, less or equal
   to MAX_FRWRDS) are referenced as forwarders from the EAT table of the import
   module with 'mod_base'. Name of the module is additionally returned under
   'pc_mod_name' (min MAX_PATH+1 long).
   The func returns TRUE on success and the count number under 'p_cnt'.
 */
static BOOL count_forwards(
    IDebugSymbols *DebugSymbols, ULONG64 mod_base, ULONG64 *p_mods,
    UINT n_mods, UINT *p_cnt, char *pc_mod_name, BOOL b_logs=FALSE)
{
    BOOL ret=FALSE;
    *p_cnt=0;

    mod_exp_dir_t ed;
    ed.mod_base = mod_base;
    if (!get_mod_exp_dir(&ed, b_logs)) goto finish;
    if (!string_cpy_lt(pc_mod_name, ed.mod_name_addr, MAX_PATH+1)) goto finish;

    DWORD ord;
    ULONG64 faddrs_addr;

    /* flags table of already found modules */
    BOOL found_mods[MAX_FRWRDS];
    memset(found_mods, 0, sizeof(found_mods));

    ret=TRUE;

    /* go through EAT looking for forwards */
    DWORD exp_proc_rva;
    for (ord=0, faddrs_addr=ed.faddrs_addr;
         ord < ed.n_faddrs;
         faddrs_addr+=sizeof(exp_proc_rva), ord++)
    {
        ULONG cb;
        if (!(read_memory(faddrs_addr, &exp_proc_rva, sizeof(exp_proc_rva), &cb)
            && cb==sizeof(exp_proc_rva))) goto finish;

        ULONG64 exp_proc_addr = RVA2ADDR(get_32uint_le(&exp_proc_rva), mod_base);

        if ((ed.exp_dd_addr <= exp_proc_addr) &&
            (exp_proc_addr < ed.exp_dd_addr+ed.exp_dd_sz))
        {
            /* forward is found, get its mod name & base */
            char frwrd_name[MAX_PATH+1];
            ULONG64 frwrd_base;

            if (!string_cpy_lt(
                frwrd_name, exp_proc_addr, sizeof(frwrd_name), '.')) continue;
            if (DebugSymbols->GetModuleByModuleName(
                frwrd_name, 0, NULL, &frwrd_base)!=S_OK) continue;

            for (UINT i=0; i<n_mods; i++)
                if (p_mods[i]==frwrd_base && !found_mods[i])
                {
                    (*p_cnt)++;
                    found_mods[i]=TRUE;
                    break;
                }
        }
    }

finish:
    return ret;
}

/* Get import module desc from index 'i' (0-based) */
static imp_mod_desc_t *get_imp_mod(const imp_mod_desc_t *p_imp_mods, UINT i)
{
    UINT j;
    const imp_mod_desc_t *p_mod = p_imp_mods;

    for (j=0; j!=i && p_mod; j++, p_mod=p_mod->next);
    if (j!=i) p_mod=NULL;

    return (imp_mod_desc_t*)p_mod;
}

/* Free all memory allocated by the imp_mods's structs */
static void free_imp_mods(imp_mod_desc_t *p_imp_mods)
{
    void *to_free;

    for (imp_mod_desc_t *mod=p_imp_mods; mod;) {
        for (imp_proc_desc_t *proc=mod->proc; proc; ) {
            to_free=proc;
            proc=proc->next;
            free(to_free);
        }
        to_free=mod;
        mod=mod->next;
        free(to_free);
    }
}

/* Free imports stored in scan imports handle */
static void free_imps_in_scan_imps_hndl(scan_imps_hndl_t *p_hndl)
{
    if (p_hndl->p_imp_mods) {
        free_imp_mods(p_hndl->p_imp_mods);
        p_hndl->p_imp_mods=NULL;
    }
    p_hndl->p_last_mod=NULL;
    p_hndl->p_last_proc=NULL;

    p_hndl->n_mods=0;
    p_hndl->crt_new_list=FALSE;
}

/* Free scan imports handle */
static void free_scan_imps_hndl(scan_imps_hndl_t *p_hndl)
{
    free_imps_in_scan_imps_hndl(p_hndl);
}

/* Initialize scan imports handle; returns TRUE on success */
static BOOL init_scan_imps_hndl(
    scan_imps_hndl_t *p_hndl, ULONG64 mod_base, BOOL b_wow_chk)
{
    BOOL ret=FALSE;
    IDebugSymbols *DebugSymbols=NULL;

    memset(p_hndl, 0, sizeof(*p_hndl));

    if ((get_client()->QueryInterface(
        __uuidof(IDebugSymbols), (void **)&DebugSymbols)) != S_OK) goto finish;

    p_hndl->mod_base = mod_base;

    ULONG64 sectab_addr;
    if (!read_pe_headers(mod_base,
        &p_hndl->dos_hdr, &p_hndl->nt_hdrs, &sectab_addr, TRUE)) goto finish;

    p_hndl->n_sects =
        read_sectab(&p_hndl->nt_hdrs, sectab_addr, p_hndl->sectab, TRUE, TRUE);
    if (!p_hndl->n_sects) goto finish;

    ULONG64 mb;
    if (b_wow_chk &&
        DebugSymbols->GetModuleByModuleName("wow64", 0, NULL, &mb)==S_OK &&
        DebugSymbols->GetModuleByModuleName("ntdll", 0, NULL, &mb)==S_OK &&
        DebugSymbols->GetModuleByModuleName("ntdll32", 0, NULL, &mb)==S_OK &&
        p_hndl->nt_hdrs.pe_tpy==pe_32bit)
    {
        p_hndl->wow64_emul = TRUE;
    }

    ret=TRUE;
finish:
    if (DebugSymbols) DebugSymbols->Release();
    if (!ret) free_scan_imps_hndl(p_hndl);
    return ret;
}

static void init_scan_imps_hndl(
    scan_imps_hndl_t *p_hndl, const dump_pe_hndl_t *p_dpe_hndl)
{
    memset(p_hndl, 0, sizeof(*p_hndl));

    p_hndl->mod_base = p_dpe_hndl->mod_base;
    p_hndl->dos_hdr = p_dpe_hndl->dos_hdr;
    p_hndl->nt_hdrs = p_dpe_hndl->nt_hdrs;

    memcpy(p_hndl->sectab,
        p_dpe_hndl->sectab, p_dpe_hndl->n_sects*sizeof(p_dpe_hndl->sectab[0]));
    p_hndl->n_sects = p_dpe_hndl->n_sects;

    /* wow64_emul is set to FALSE */
}

/* Resolve forwarder redirection string pointed by 'frwrd_name_addr' (the string
   in the format "module.proc_name" or "module.#ordinal") to the forwarder proc
   address. The function tries to resolve forwards to forwards until the final
   code reference. Returns TRUE on success.
 */
static BOOL get_frwrd_proc_addr(scan_imps_hndl_t *p_hndl,
    ULONG64 frwrd_name_addr, ULONG64 *p_reslv_addr, BOOL b_logs=FALSE)
{
    BOOL ret=FALSE;

    IDebugSymbols *DebugSymbols=NULL;
    if ((get_client()->QueryInterface(
        __uuidof(IDebugSymbols), (void **)&DebugSymbols)) != S_OK) goto finish;

    char mod_name[MAX_PATH+1];
    char proc_name[MAX_SYM_NAME+1];

    {
        /* read module and proc name from forwarder string */
        char rd_buf[sizeof(mod_name)+sizeof(proc_name)+4];
        if (!string_cpy_lt(rd_buf, frwrd_name_addr, sizeof(rd_buf))) goto finish;

        /* mod name separated from proc name by '.' */
        char *pc_dot = strchr(rd_buf, '.');
        if (!pc_dot) {
            if (b_logs) err_dbgprintf("Invalid forwarder name: %s\n", rd_buf);
            goto finish;
        }

        *pc_dot++ = 0;
        strncpy(proc_name, pc_dot, sizeof(proc_name));
        proc_name[sizeof(proc_name)-1] = 0;

        if (p_hndl->wow64_emul && !strcmpi(rd_buf, "ntdll")) {
            /* on emulated subsystem ntdll is substituted by the ntdll32 lib by
               the Wow64 emulator; we need to search in the 32-bit version of
               the library */
            strcpy(mod_name, "ntdll32");
        } else {
            strncpy(mod_name, rd_buf, sizeof(mod_name));
            mod_name[sizeof(mod_name)-1] = 0;
        }
    }

    ULONG64 mod_base;
    if (DebugSymbols->GetModuleByModuleName(mod_name, 0, NULL, &mod_base)!=S_OK)
    {
        if (b_logs)
            err_dbgprintf("Unable to find the forwarder's module: %s\n", mod_name);
        goto finish;
    }

    /* check if the cache may be used */
    mod_exp_dir_t *p_ed = &p_hndl->ed_frwrd;
    if (p_ed->mod_base != mod_base) {
        p_ed->mod_base = mod_base;
        if (!get_mod_exp_dir(p_ed, b_logs)) goto finish;
    }

    ULONG cb;
    DWORD ord;      /* index in EAT */
    const char *pc_ord = strchr(proc_name, '#');

    if (pc_ord)
    {
        /* proc given by an ordinal number */
        pc_ord++;

        errno = 0;
        ord = strtoul(pc_ord, NULL, 10);
        if (errno) {
            if (b_logs)
                err_dbgprintf("Forwarder's ordinal number conversion "
                    "problem: %s\n", &proc_name[0]);
            goto finish;
        }
        if (ord < p_ed->ord_base) {
            if (b_logs)
                err_dbgprintf("Forwarder's ordinal number [0x%04X] larger than "
                    "the ordinal base [0x%04X]\n", ord, p_ed->ord_base);
            goto finish;
        }
        ord = ord-p_ed->ord_base;
    } else
    {
        /* proc given by name */
        DWORD hint;
        if (!get_name_hint_ord(p_ed, proc_name, &hint, &ord)) {
            if (b_logs)
                err_dbgprintf("Can't find forwarder's proc with the name: %s\n",
                proc_name);
            goto finish;
        }
    }

    /* get forwarder proc addr basing on the EAT index */
    DWORD proc_rva;
    if (!(read_memory(p_ed->faddrs_addr + ord*sizeof(proc_rva),
        &proc_rva, sizeof(proc_rva), &cb) && cb==sizeof(proc_rva))) goto finish;

    ULONG64 proc_addr = RVA2ADDR(get_32uint_le(&proc_rva), p_ed->mod_base);

    if ((p_ed->exp_dd_addr <= proc_addr) &&
        (proc_addr < p_ed->exp_dd_addr+p_ed->exp_dd_sz))
    {
        /* if the resolved proc is forwarder we need to recursively resolve it */
        ret = get_frwrd_proc_addr(p_hndl, proc_addr, p_reslv_addr, b_logs);
    } else {
        *p_reslv_addr = proc_addr;
        ret=TRUE;
    }

finish:
    if (DebugSymbols) DebugSymbols->Release();
    return ret;
}

/* Get the export information from a dll module about a proc pointed by the
  'proc_addr'. 'ords', 'hints' and 'proc_names' are populated with the info
   from the dll's export tab. These tabs have the same number of output elements
   stored on response under the addr of 'p_n_synons'. If an elem in the
   'proc_names' is NULL, then the corresponding item has no name (only an
   ordinal). The pointers of 'proc_names' point to addresses in the
   'pc_names_buf' with the length 'names_buf_sz'. If 'p_proc_mod_base' points to
   value other than NULL, the value indicates the module base address used for
   resolving the proc_addr. If the value is NULL the owning module of the
   proc_addr will be used. 'p_proc_mod_base' will be set to the owning module base.
   'pc_mod_name' points to value other than NULL, it will get the owner's module
   name. Min size of this buf is MAX_PATH+1. If 'b_logs' is TRUE print error info.
   Returns TRUE for success, FALSE - error or 'proc_addr' not found.
 */
static BOOL get_exp_proc_info(scan_imps_hndl_t *p_hndl, ULONG64 *p_proc_mod_base,
    ULONG64 proc_addr, DWORD ords[MAX_SYNONS], DWORD hints[MAX_SYNONS],
    char* (proc_names)[MAX_SYNONS], char *pc_names_buf, size_t names_buf_sz,
    DWORD *p_n_synons, char *pc_mod_name, BOOL b_logs)
{
    BOOL ret=FALSE;
    IDebugSymbols *DebugSymbols=NULL;

    /* requested module base to search */
    ULONG64 srch_mod_base = *p_proc_mod_base;
    /* owning proc module base */
    ULONG64 own_mod_base = NULL;

    *p_n_synons=0;

    if ((get_client()->QueryInterface(
        __uuidof(IDebugSymbols), (void **)&DebugSymbols)) != S_OK) goto err;

    if (DebugSymbols->GetModuleByOffset(proc_addr, 0, NULL, &own_mod_base)!=S_OK)
    {
        if (b_logs)
            err_dbgprintf("Unable to find a module owning the proc addr: 0x%p\n",
                proc_addr);
        goto err;
    }

    *p_proc_mod_base = own_mod_base;
    if (srch_mod_base==NULL) srch_mod_base=own_mod_base;

    /* check if the cache may be used */
    mod_exp_dir_t *p_ed = &p_hndl->ed_reslv;
    if (p_ed->mod_base != srch_mod_base) {
        p_ed->mod_base = srch_mod_base;
        if (!get_mod_exp_dir(p_ed, b_logs)) goto err;
    }

    ULONG cb;
    BOOL forwd_resv;

    for (UINT pass=0; *p_n_synons==0 && pass<2; pass++)
    {
        if (pass==0) {
            /* at the 1st resolving pass, forwards are resolved only for
               proc located in external module to the currently searched */
            forwd_resv = (srch_mod_base!=own_mod_base);
        } else {
            /* at the 2nd pass additionally resolve
               forwards to the owning module */
            if (forwd_resv) break;
            else
            if ((p_ed->exp_dd_addr <= proc_addr) &&
                (proc_addr < p_ed->exp_dd_addr+p_ed->exp_dd_sz)) break;
            else
                forwd_resv=TRUE;
        }

        DWORD ord;
        ULONG64 faddrs_addr;

        /* go through Export Address Table looking for the proc_addr */
        DWORD exp_proc_rva;
        for (ord=0, faddrs_addr=p_ed->faddrs_addr;
             ord < p_ed->n_faddrs;
             faddrs_addr+=sizeof(exp_proc_rva), ord++)
        {
            if (!(read_memory(
                faddrs_addr, &exp_proc_rva, sizeof(exp_proc_rva), &cb) &&
                cb==sizeof(exp_proc_rva))) goto err;

            ULONG64 exp_proc_addr =
                RVA2ADDR(get_32uint_le(&exp_proc_rva), srch_mod_base);

            if (forwd_resv && (p_ed->exp_dd_addr <= exp_proc_addr) &&
                (exp_proc_addr < p_ed->exp_dd_addr+p_ed->exp_dd_sz))
            {
                /* the exported address is a forward reference; we need to
                   convert this address to the actual address inside the
                   referenced module */
                if (!get_frwrd_proc_addr(p_hndl, exp_proc_addr, &exp_proc_addr))
                    continue;
            }

            if (exp_proc_addr==proc_addr) {
                if (*p_n_synons < MAX_SYNONS) {
                    ords[(*p_n_synons)++] = p_ed->ord_base+ord;
                    /* don't brake and search for more entries with the same addr */
                } else {
                    if (b_logs) {
                        warn_dbgprintf(
                            "Too much symbols with the same addr [0x%p] in the "
                            "module (base: 0x%p); break searching for more "
                            "symbol duplicates for this addr\n",
                            proc_addr, srch_mod_base);
                    }
                    break;
                }
            }
        }
    }

    if (*p_n_synons==0) {
        if (b_logs)
            err_dbgprintf("Unable to find the proc for the addr: 0x%p\n",
                proc_addr);
        goto err;
    }

    /* look for the names for the found ordinals */
    size_t alloc_bts=0;
    for (DWORD i=0; i<*p_n_synons; i++)
    {
        ULONG64 fords_addr = p_ed->fords_addr;
        proc_names[i] = NULL;
        hints[i] = 0;

        WORD ot_ord;    /* ord read from the ordinals table */
        for (DWORD hint=0;
            hint < p_ed->n_fnames;
            fords_addr+=sizeof(ot_ord), hint++)
        {
            if (!(read_memory(fords_addr,
                &ot_ord, sizeof(ot_ord), &cb) && cb==sizeof(ot_ord))) goto err;

            ot_ord = get_16uint_le(&ot_ord);

            if (ords[i]==p_ed->ord_base+(DWORD)ot_ord)
            {
                DWORD proc_name_rva;
                char buf[MAX_SYM_NAME+1];

                /* read proc name address */
                if (!(read_memory(p_ed->fnames_addr + hint*sizeof(proc_name_rva),
                    &proc_name_rva, sizeof(proc_name_rva), &cb) &&
                    cb==sizeof(proc_name_rva))) goto err;

                /* ... and store the proc name */
                ULONG64 proc_name_addr =
                    RVA2ADDR(get_32uint_le(&proc_name_rva), srch_mod_base);
                if (!string_cpy_lt(buf, proc_name_addr, sizeof(buf))) goto err;

                size_t name_len = strlen(buf);

                /* ... in the names_buf */
                if (alloc_bts+name_len+1 <= names_buf_sz) {
                    proc_names[i] = pc_names_buf+alloc_bts;
                    alloc_bts += name_len+1;
                    strcpy(proc_names[i], buf);

                    hints[i] = hint;
                } else {
                    if (b_logs)
                        warn_dbgprintf(
                            "Buffer too small to store proc name %s [0x%p] from "
                            "module (base: 0x%p)", buf, proc_addr, srch_mod_base);
                }
                break;
            }
        }
    }

    /* store mod name */
    if (pc_mod_name)
        if (!string_cpy_lt(pc_mod_name, p_ed->mod_name_addr, MAX_PATH+1))
            goto err;

no_err:
    ret=TRUE;
err:
    if (DebugSymbols) DebugSymbols->Release();
    return ret;
}

/* Resolve proc name, its ord, hint and write them under 'p_out_ord', 'p_out_hint'
   and 'pc_out_proc_name' (min MAX_PATH+1 long). Number of entries with the same
   'proc_addr' is returned under the 'p_n_synons'. Returns TRUE if the resolution
   finishes with success, FALSE otherwise.
 */
static BOOL resv_proc_name_mod(scan_imps_hndl_t *p_hndl, ULONG64 mod_base,
    ULONG64 proc_addr, DWORD *p_out_ord, DWORD *p_out_hint, char *pc_out_proc_name,
    DWORD *p_n_synons, BOOL b_logs)
{
    BOOL ret=FALSE;

    DWORD n_synons;
    DWORD ords[MAX_SYNONS];
    DWORD hints[MAX_SYNONS];
    char* (proc_names)[MAX_SYNONS];
    char name_buf[0x1000];
    char mod_name[MAX_PATH+1];
    ULONG64 proc_mod_base = mod_base;

    if (!get_exp_proc_info(p_hndl, &proc_mod_base, proc_addr, ords, hints,
         proc_names, name_buf, sizeof(name_buf), &n_synons, mod_name, b_logs))
         goto finish;

    DWORD i;
    *p_n_synons = n_synons;

    /* The resolved proc is:
       - the 1st matching proc with a name
       - the 1st ord if the proc doesn't have any name */
    for (i=0; i<n_synons; i++) {
        if (proc_names[i]) {
            *p_out_ord = ords[i];
            *p_out_hint = hints[i];
            strncpy(pc_out_proc_name, proc_names[i], MAX_PATH+1);
            pc_out_proc_name[MAX_PATH]=0;
            break;
        }
    }
    if (i>=n_synons) {
        *p_out_ord = ords[0];
        *p_out_hint = 0;
        *pc_out_proc_name = 0;
    }

    if (n_synons>1)
    {
        /* printed regardless of b_logs flag - the func finished with
           success but there is a need to inform about the duplicates */
        warn_dbgprintf(
            "Proc with many aliases has been found [0x%p]: ", proc_addr);
        for (i=0; i<n_synons; i++) {
            dbgprintf("%s#0x%04X%s", (proc_names[i] ? proc_names[i] : ""),
                ords[i], (i+1<n_synons ? ", " : ""));
        }
        dbgprintf("\n  Resolved to: %s!%s#0x%04X\n",
                mod_name, pc_out_proc_name, *p_out_ord);
    }

    ret=TRUE;
finish:
    return ret;
}

/* Info about proc duplicates in the lastly resolved module's list of imports */
static void print_info_proc_dups(const scan_imps_hndl_t *p_hndl)
{
    BOOL hdr_printed=FALSE;
    const char *sep = " ";

    /* are there any modules loaded? */
    if (!p_hndl->p_imp_mods) goto finish;

    for (const imp_proc_desc_t *p_proc = p_hndl->p_last_mod->proc;
        p_proc != p_hndl->p_last_proc;
        p_proc=p_proc->next)
    {
        if (p_proc->dups>0)
        {
            const char *pc_mod_name = (*(p_hndl->p_last_mod->name) ?
                p_hndl->p_last_mod->name : "<unspec>");

            if (!hdr_printed)
                warn_dbgprintf("Found duplicates in a module %s:", pc_mod_name);
            hdr_printed = TRUE;

            dbgprintf("%s%s#0x%04X [%d]",
                sep, p_proc->name, p_proc->ord, p_proc->dups+1);
            sep = ", ";
        }
    }
    if (hdr_printed) dbgprintf("\n");

finish:
    return;
}

/* Info about module duplicates in the resolved list of imports */
static void print_info_mod_dups(const scan_imps_hndl_t *p_hndl)
{
    BOOL hdr_printed=FALSE;
    const char *sep = " ";

    for (const imp_mod_desc_t *p_mod = p_hndl->p_imp_mods;
        p_mod != p_hndl->p_last_mod;
        p_mod = p_mod->next)
    {
        if (p_mod->dups>0 && *(p_mod->name))
        {
            if (!hdr_printed) info_dbgprintf("Duplicated modules found:");
            hdr_printed = TRUE;

            dbgprintf("%s%s [%d]", sep, p_mod->name, p_mod->dups+1);
            sep = ", ";
        }
    }
    if (hdr_printed) dbgprintf("\n");
}

/* Mark end of a module's imports list */
static void mark_end_mod_imp_list(scan_imps_hndl_t *p_hndl)
{
    p_hndl->crt_new_list = TRUE;

    if (p_hndl->p_imp_mods)
    {
        if (*(p_hndl->p_last_mod->name))
        {
            if (p_hndl->wow64_emul &&
                !strcmpi(p_hndl->p_last_mod->name, "ntdll32.dll"))
            {
                /* for 32-bit target emulated on Wow64 platform the ntdll32 is
                   an alias to ntdll, whereas ntdll itself is a 64-bit version
                   of the library; therefore we need to rename the ntdll32 to
                   ntdll keeping all ordinals, hints and proc names untouched */

                /* even num of bytes, enough name space */
                strcpy(p_hndl->p_last_mod->name, "ntdll.dll");
            }

            /* calculate dups of the added module */
            for (imp_mod_desc_t *p_mod = p_hndl->p_imp_mods;
                p_mod != p_hndl->p_last_mod;
                p_mod = p_mod->next)
            {
                if (!strcmpi(p_mod->name, p_hndl->p_last_mod->name)) {
                    p_mod->dups++;
                    break;
                }
            }
        }

        print_info_proc_dups(p_hndl);
    }

finish:
    return;
}

/* Compare 2 proc; returns TRUE is the same */
inline static BOOL cmp_procs(const char *pc_proc1_name,
    DWORD proc1_ord, const char *pc_proc2_name, DWORD proc2_ord)
{
    BOOL ret=FALSE;

    if (*pc_proc1_name && *pc_proc2_name)
        ret = !strcmp(pc_proc1_name, pc_proc2_name);
    else
        ret = (proc1_ord==proc2_ord);

    return ret;
}


/* Add importing module to the scan imports handle's list */
static BOOL add_imp_mod(scan_imps_hndl_t *p_hndl,
    ULONG64 mod_iat_addr, ULONG64 mod_base, const char *pc_proc_mod_name)
{
    BOOL ret=FALSE;

    size_t proc_mod_name_len = strlen(pc_proc_mod_name);

    imp_mod_desc_t *p_new_mod_desc;
    size_t to_alloc = sizeof(*p_new_mod_desc)+proc_mod_name_len+4;
    p_new_mod_desc = (imp_mod_desc_t*)malloc(to_alloc);

    if (!p_new_mod_desc) goto finish;

    p_new_mod_desc->mod_base = mod_base;
    p_new_mod_desc->iat_addr = mod_iat_addr;
    p_new_mod_desc->n_procs = 0;
    p_new_mod_desc->proc = NULL;
    p_new_mod_desc->dups = 0;
    p_new_mod_desc->hnt_sz = 0;
    p_new_mod_desc->hnt_nrnd_sz = 0;
    p_new_mod_desc->next = NULL;
    strcpy(p_new_mod_desc->name, pc_proc_mod_name);
    /* even padd byte */
    if (!(proc_mod_name_len&1)) p_new_mod_desc->name[proc_mod_name_len+1]=0;

    if (p_hndl->p_imp_mods)
        p_hndl->p_last_mod->next = p_new_mod_desc;
    else
        p_hndl->p_imp_mods = p_new_mod_desc;

    p_hndl->p_last_mod = p_new_mod_desc;
    p_hndl->p_last_proc = NULL;
    p_hndl->crt_new_list = FALSE;
    p_hndl->n_mods++;

    ret=TRUE;
finish:
    return ret;
}

/* Add to the scan imports handle's list of procs of an importing module. If
   required the importing module itself may also be added. The input params
   as returned by the resv_proc_name_mod(). TRUE returned on success. FALSE: no
   memory error.
 */
static BOOL add_imp_mod_proc(scan_imps_hndl_t *p_hndl, DWORD ord, DWORD hint,
    const char *pc_proc_name, ULONG64 mod_iat_addr, ULONG64 mod_base,
    const char *pc_proc_mod_name, BOOL b_check_proc_dups)
{
    BOOL ret=FALSE;

    /* create new mod's list if required */
    if (!p_hndl->p_imp_mods || p_hndl->crt_new_list) {
        if (!add_imp_mod(p_hndl, mod_iat_addr, mod_base, pc_proc_mod_name))
            goto finish;
    }

    /* add proc name to the current module's list */
    size_t proc_name_len = strlen(pc_proc_name);

    imp_proc_desc_t *p_new_proc_desc;
    size_t to_alloc = sizeof(*p_new_proc_desc)+proc_name_len+4;
    p_new_proc_desc = (imp_proc_desc_t*)malloc(to_alloc);

    if (!p_new_proc_desc) goto finish;

    p_new_proc_desc->ord = ord;
    p_new_proc_desc->hint = (proc_name_len>0 ? hint : (DWORD)-1);
    p_new_proc_desc->dups = 0;
    p_new_proc_desc->next = NULL;
    strcpy(p_new_proc_desc->name, pc_proc_name);
    /* even padd byte */
    if (!(proc_name_len&1)) p_new_proc_desc->name[proc_name_len+1]=0;

    if (p_hndl->p_last_proc)
        p_hndl->p_last_proc->next = p_new_proc_desc;
    else
        p_hndl->p_last_mod->proc = p_new_proc_desc;

    p_hndl->p_last_proc = p_new_proc_desc;

    p_hndl->p_last_mod->n_procs++;
    if (proc_name_len>0) {
        p_hndl->p_last_mod->hnt_sz += 2+RNDUP_W(proc_name_len+1);
        p_hndl->p_last_mod->hnt_nrnd_sz += 2+proc_name_len+1;
    }

    /* if it's been requested check against duplicates of the newly added proc */
    if (b_check_proc_dups)
    {
        for (imp_proc_desc_t *p_proc = p_hndl->p_last_mod->proc;
            p_proc != p_hndl->p_last_proc;
            p_proc=p_proc->next)
        {
            if (cmp_procs(p_proc->name, p_proc->ord, pc_proc_name, ord)) {
                p_proc->dups++;
                break;
            }
        }
    }

    ret=TRUE;
finish:
    return ret;
}

/* Return current module index (1-based) */
inline static void get_mod_idx(const scan_imps_hndl_t *p_hndl, DWORD *p_mod_i)
{
    if (p_hndl->p_imp_mods)
        *p_mod_i = p_hndl->n_mods + (p_hndl->crt_new_list ? 1 : 0);
    else
        *p_mod_i = 1;
}

/* Search for a module name of the one being currently resolved in the modules
   conflict resolvers specification. Returns TRUE if found and set under address
   'pc_mod_name' (min MAX_PATH+1 long).
 */
static BOOL get_mod_confl_spec(const scan_imps_hndl_t *p_hndl, char *pc_mod_name)
{
    BOOL ret=FALSE;

    DWORD mod_i=0;
    get_mod_idx(p_hndl, &mod_i);

    char cfgprm[10];
    sprintf(cfgprm, "%d", mod_i);

    if (GetPrivateProfileString(PROP_SECT_CONFLSPEC,
        cfgprm, "", pc_mod_name, MAX_PATH+1, PROP_FILE)>0) ret=TRUE;
    pc_mod_name[MAX_PATH]=0;

finish:
    return ret;
}

/* Recognize an owning module of an IAT table at the address 'mod_iat_addr'.
   Name and the base address of the module are written under 'pc_mod_name'
   (min MAX_PATH+1 long) and 'p_mod_base' respectively. Returns TRUE on success.
 */
static BOOL get_owning_mod(scan_imps_hndl_t *p_hndl, ULONG64 mod_iat_addr,
    char *pc_mod_name, ULONG64 *p_mod_base, BOOL b_logs)
{
    BOOL ret=FALSE;

    IDebugSymbols *DebugSymbols=NULL;
    if ((get_client()->QueryInterface(
        __uuidof(IDebugSymbols), (void **)&DebugSymbols)) != S_OK) goto finish;

    if (get_mod_confl_spec(p_hndl, pc_mod_name))
    {
        /* the owning module is the one specified in the conflict resolvers spec.
         */

        /* get module name w/o extension as required by the debug API */
        char mod_name[MAX_PATH+1];
        get_file_name(pc_mod_name, mod_name, sizeof(mod_name));

        if (DebugSymbols->GetModuleByModuleName(
            mod_name, 0, NULL, p_mod_base)!=S_OK)
        {
            if (b_logs)
                err_dbgprintf("Unable to find the module: %s\n", mod_name);
            goto finish;
        }
    } else
    {
        /* There is a need to recognize the owning module; the following steps
           are performed:
           1. Find all modules referenced by the importing procs of a given
              IAT table,
           2. For each of the module, count forwards which reference to the
              modules from step 1,
           3. The owning module is assumed to be the one with maximal number of
              the references from step 2.
         */

        /* step 1
         */
        UINT n_mods;
        ULONG64 mods[MAX_FRWRDS];   /* process max 32 modules in the IAT */

        ULONG64 iat_elem_addr=mod_iat_addr;
        DWORD iat_elem_len = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
            sizeof(IMAGE_THUNK_DATA32) : sizeof(IMAGE_THUNK_DATA64));

        for (n_mods=0; n_mods<MAX_FRWRDS; iat_elem_addr+=iat_elem_len)
        {
            ULONG cb;
            ULONG64 proc_addr;

            /* get proc address */
            if (!(read_memory(iat_elem_addr, &proc_addr, iat_elem_len, &cb) &&
                cb==iat_elem_len)) break;
            proc_addr = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
                DEBUG_EXTEND64(get_32uint_le(&proc_addr)) :
                get_64uint_le(&proc_addr));
            if (!proc_addr) break;

            UINT i;
            ULONG64 mod;

            /* get proc's mod and add it to the table (if not already exists) */
            if (DebugSymbols->GetModuleByOffset(proc_addr, 0, NULL, &mod)!=S_OK)
                break;
            for (i=0; i<n_mods; i++) if (mods[i]==mod) break;
            if (i>=n_mods) mods[n_mods++]=mod;
        }

        if (!n_mods) {
            if (b_logs) {
                err_dbgprintf(
                    "Can not recognize any module from the IAT table at 0x%p\n",
                    mod_iat_addr);
            }
            goto finish;
        }

        /* step 2 & 3
         */

        /* mods index of the module with max number of compliant forwards */
        UINT mf_ind=0;
        /* current value of max compliant forwards */
        UINT mf_val=(UINT)-1;
        char mod_name[MAX_PATH+1];

        for (UINT i=0; i<n_mods; i++)
        {
            UINT mf_val_i;
            BOOL cf_ret = count_forwards(
                DebugSymbols, mods[i], mods, n_mods, &mf_val_i, mod_name);

            if (cf_ret && (mf_val==(UINT)-1 || mf_val_i>mf_val))
            {
                mf_val=mf_val_i;
                mf_ind=i;

                *p_mod_base = mods[mf_ind];
                strcpy(pc_mod_name, mod_name);
            }
        }

        if (mf_val==(UINT)-1) {
            if (b_logs) {
                err_dbgprintf(
                    "Can not recognize owning module of the IAT table at 0x%p\n",
                    mod_iat_addr);
            }
            goto finish;
        }
    }

    ret=TRUE;
finish:
    if (DebugSymbols) DebugSymbols->Release();
    return ret;
}

/* Get name and base addr of a module whose list of imports is currently
   populated. In case of success return TRUE, FALSE - no current module
   established.
 */
inline BOOL get_last_mod_info(const scan_imps_hndl_t *p_hndl,
    const char **ppc_mod_name, ULONG64 *p_mod_base)
{
    BOOL ret=FALSE;

    if (p_hndl->p_imp_mods && !p_hndl->crt_new_list)
    {
        *ppc_mod_name = p_hndl->p_last_mod->name;
        *p_mod_base = p_hndl->p_last_mod->mod_base;

        ret=TRUE;
    }

    return ret;
}

/* Process single IAT entry element. 'mod_iat_addr' is the address of the
   module's IAT table where the 'proc_addr' to resolve, belongs. In case of
   success the func returns TRUE.
 */
static BOOL process_iat_elem(scan_imps_hndl_t *p_hndl,
    ULONG64 mod_iat_addr, ULONG64 proc_addr, BOOL b_logs)
{
    BOOL ret=FALSE;

    DWORD ord, hint;
    const char *pc_mod_name;
    char proc_name[MAX_SYM_NAME+12];
    char reslv_mod_name[MAX_PATH+1];
    ULONG64 mod_base;
    BOOL b_check_proc_dups=FALSE;

    if (!get_last_mod_info(p_hndl, &pc_mod_name, &mod_base))
    {
        /* recognize the owning module */
        if (!get_owning_mod(
            p_hndl, mod_iat_addr, reslv_mod_name, &mod_base, b_logs))
        {
            if (b_logs)
                err_dbgprintf("Can not establish an owning module for "
                    "the IAT table starting at: 0x%p\n", mod_iat_addr);
            goto finish;
        }
        pc_mod_name = reslv_mod_name;
    }

    /* resolve proc addresses into its name, ordinal, hint */
    DWORD n_synons;
    if (!resv_proc_name_mod(
        p_hndl, mod_base, proc_addr, &ord, &hint, proc_name, &n_synons, b_logs))
        goto finish;

    /* For performance reason proc duplicates are checked only if IAT table has
       more than one entry with the same imported address; in normal case this
       is the only reason when there may occur duplicates in the rebuild list of
       imports
     */
    if (n_synons>1) b_check_proc_dups=TRUE;

    /* add a new proc to the list of imported procs of the current module */
    ret = add_imp_mod_proc(p_hndl, ord, hint, proc_name,
        mod_iat_addr, mod_base, pc_mod_name, b_check_proc_dups);

finish:
    return ret;
}

/* Print imports specification */
static void print_imp_spec(const scan_imps_hndl_t *p_hndl)
{
    DWORD i, j;
    const imp_mod_desc_t *p_mod;
    const imp_proc_desc_t *p_proc;

    dbgprintf("[%s]\n", PROP_SECT_IMPSPEC);

    for (p_mod=p_hndl->p_imp_mods, i=1;
        p_mod;
        p_mod=p_mod->next, i++)
    {
        if (*(p_mod->name)) dbgprintf("%d = %s\n", i, p_mod->name);
        dbgprintf("%d.%s = 0x%08X\n", i,
            PROP_IMPSPEC_IAT_RVA, ADDR2RVA(p_mod->iat_addr, p_hndl->mod_base));

        for (p_proc=p_mod->proc, j=1; p_proc; p_proc=p_proc->next, j++)
        {
            dbgprintf("%d.%d = %s", i, j, p_proc->name);
            if (strlen(p_proc->name)) dbgprintf("\n");
            else dbgprintf("#0x%04X\n", p_proc->ord);
        }
    }
}

/* Process IDT table to populate the modules list. Address of the table is passed
   by 'idt_addr'. 'idt_sz' contains size constraint of the table to process
   ((DWORD)-1 if unlimited). Returns TRUE on success.
 */
static BOOL process_idt(scan_imps_hndl_t *p_hndl, ULONG64 idt_addr, DWORD idt_sz)
{
    BOOL ret=FALSE;

    DWORD idt_sz_proc=0;
    ULONG64 idt_elem_addr=idt_addr;

    DWORD iat_elem_len = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
        sizeof(IMAGE_THUNK_DATA32) : sizeof(IMAGE_THUNK_DATA64));

    IMAGE_IMPORT_DESCRIPTOR idt_ent;
    for (;; idt_elem_addr+=sizeof(idt_ent), idt_sz_proc+=sizeof(idt_ent))
    {
        /* we may be confined by the IDT size */
        if (idt_sz!=(DWORD)-1 && idt_sz_proc>=idt_sz) break;

        ULONG cb;

        /* get IDT entry */
        if (!(read_memory(idt_elem_addr, &idt_ent, sizeof(idt_ent), &cb) &&
            cb==sizeof(idt_ent))) goto finish;

        /* zeroed entry marks end of the IDT table */
        if (!rmemchr(&idt_ent, 0, sizeof(idt_ent))) break;

        ULONG64 iat_elem_addr =
            RVA2ADDR(get_32uint_le(&idt_ent.FirstThunk), p_hndl->mod_base);

        ULONG64 mod_iat_addr;
        BOOL b_new_iat=TRUE;

        for (;; iat_elem_addr+=iat_elem_len)
        {
            ULONG64 proc_addr;

            /* get proc address */
            if (!(read_memory(iat_elem_addr, &proc_addr, iat_elem_len, &cb) &&
                cb==iat_elem_len)) goto finish;

            proc_addr = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
                DEBUG_EXTEND64(get_32uint_le(&proc_addr)) :
                get_64uint_le(&proc_addr));

            if (!proc_addr)
            {
                /* last proc of a module has been reached */
                mark_end_mod_imp_list(p_hndl);
                break;
            }

            /* remember beginning of the IAT for the currently resolving module */
            if (b_new_iat) mod_iat_addr=iat_elem_addr;

            if (!process_iat_elem(p_hndl, mod_iat_addr, proc_addr, TRUE)) {
                err_dbgprintf("Unresolved proc addr: 0x%p", proc_addr);
                goto finish;
            }

            b_new_iat=FALSE;
        }
    }

    ret=TRUE;

finish:
    if (!ret)
    {
        if (p_hndl->n_mods) {
            dbgprintf(", currently resolved imports:\n");
            print_imp_spec(p_hndl);
        } else
            dbgprintf("\n");
    }
    return ret;
}

/* Process IAT table (of each importing module) to populate the modules list.
   Address of the IAT table under 'iat_addr'. 'iat_sz' contains max. size of the
   IAT to process ((DWORD)-1 if unlimited). If 'p_proc_sz' is not NULL a number
   of processed bytes will be written there. Returns TRUE on success.
 */
static BOOL process_iat(
    scan_imps_hndl_t *p_hndl, ULONG64 iat_addr, DWORD iat_sz, DWORD *p_proc_sz)
{
    BOOL ret=FALSE;
    IDebugSymbols *DebugSymbols=NULL;

    if ((get_client()->QueryInterface(__uuidof(IDebugSymbols),
        (void **)&DebugSymbols)) != S_OK) goto finish;

    BOOL b_iat_rd=FALSE;            /* IAT table read indicator */
    DWORD iat_sz_proc=0, step_sz;
    ULONG64 iat_elem_addr=iat_addr, mod_iat_addr;
    DWORD iat_elem_len = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
        sizeof(IMAGE_THUNK_DATA32) : sizeof(IMAGE_THUNK_DATA64));

    /* go thru all entries of the IAT per every module to
       populate the list of modules with their imports */
    for (;; iat_elem_addr+=step_sz, iat_sz_proc+=step_sz)
    {
        /* we may be confined by the IAT size */
        if (iat_sz!=(DWORD)-1 && iat_sz_proc>=iat_sz) break;

        ULONG cb;
        ULONG64 proc_addr;

        /* get proc address */
        if (!(read_memory(
            iat_elem_addr, &proc_addr, iat_elem_len, &cb) && cb==iat_elem_len))
        {
            if (!b_iat_rd) break;
            else goto finish;
        }
        proc_addr = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
            DEBUG_EXTEND64(get_32uint_le(&proc_addr)) : get_64uint_le(&proc_addr));

        step_sz = iat_elem_len;

        if (!b_iat_rd)
        {
            /* no IAT already being read */
            ULONG64 own_mod_base;

            if (!proc_addr || DebugSymbols->GetModuleByOffset(
                proc_addr, 0, NULL, &own_mod_base)!=S_OK ||
                !process_iat_elem(p_hndl, iat_elem_addr, proc_addr, FALSE))
            {
                /* ignore gaps between IAT tables */
                step_sz = 1;
            } else
            {
                /* start of a new IAT table detected */
                b_iat_rd = TRUE;
                mod_iat_addr = iat_elem_addr;
            }
        } else
        if (!proc_addr)
        {
            /* last proc of a module has been reached */
            mark_end_mod_imp_list(p_hndl);
            b_iat_rd = FALSE;
        } else
        {
            /* process IAT elem */
            if (!process_iat_elem(p_hndl, mod_iat_addr, proc_addr, TRUE)) {
                err_dbgprintf("Unresolved proc addr: 0x%p", proc_addr);
                goto finish;
            }
        }
    }

    ret=TRUE;

finish:
    if (DebugSymbols)
    {
        DebugSymbols->Release();

        if (!ret) {
            if (p_hndl->n_mods) {
                dbgprintf(", currently resolved imports:\n");
                print_imp_spec(p_hndl);
            } else dbgprintf("\n");
        }
    }
    if (p_proc_sz) *p_proc_sz = (DWORD)(iat_elem_addr-iat_addr);
    return ret;
}

/* exported; see header for details */
void scan_imports(ULONG64 mod_base,
    iscan_tpy_t iscan_tpy, const rng_spec_t *p_rng, DWORD flags)
{
    BOOL b_fihndl=FALSE;
    scan_imps_hndl_t hndl;

    if (!init_scan_imps_hndl(&hndl, mod_base, TRUE)) goto finish;
    else b_fihndl=TRUE;

    DWORD idt_rva=0, idt_sz=0, iat_rva=0, iat_sz=0;
    if (!p_rng) {
        if (iscan_tpy==iscan_idt) {
            IMAGE_DATA_DIRECTORY *p_dd_idt;
            if (get_data_dir(
                &hndl.nt_hdrs, IMAGE_DIRECTORY_ENTRY_IMPORT, &p_dd_idt, FALSE))
            {
                idt_rva=get_32uint_le(&p_dd_idt->VirtualAddress);
                idt_sz=get_32uint_le(&p_dd_idt->Size);
            }

            if (!idt_rva || !idt_sz) {
                info_dbgprintf("No IDT table in the module\n");
                goto finish;
            }
        } else {
            IMAGE_DATA_DIRECTORY *p_dd_iat;
            if (get_data_dir(
                &hndl.nt_hdrs, IMAGE_DIRECTORY_ENTRY_IAT, &p_dd_iat, FALSE))
            {
                iat_rva=get_32uint_le(&p_dd_iat->VirtualAddress);
                iat_sz=get_32uint_le(&p_dd_iat->Size);
            }

            if (!iat_rva || !iat_sz) {
                info_dbgprintf("No IAT table in the module\n");
                goto finish;
            }
        }
    }

    ULONG64 scan_addr;
    DWORD scan_len;

    if (iscan_tpy==iscan_idt)
    {
        /* IDT scanning mode */
        if (p_rng) {
            if (p_rng->is_sect) goto finish;
            scan_addr = (p_rng->rng.is_rva ?
                RVA2ADDR(p_rng->rng.rva, mod_base) : p_rng->rng.addr);
            if (!scan_addr || !p_rng->rng.len) goto finish;
            scan_len = p_rng->rng.len;
        } else {
            scan_addr = RVA2ADDR(idt_rva, mod_base);
            scan_len = idt_sz;
        }

        info_dbgprintf("IDT scanning starts at: 0x%p", scan_addr);
        if (scan_len!=(DWORD)-1)
            dbgprintf(", size constraint: 0x%04X\n", scan_len);
        else
            dbgprintf("\n");

        if (!process_idt(&hndl, scan_addr, scan_len)) goto finish;
    } else
    {
        /* IAT scanning mode */
        DWORD proc_len;

        if (p_rng && p_rng->is_sect)
        {
            DWORD start_sect, end_sect;
            if (p_rng->sect==(DWORD)-1) {
                start_sect = 0;
                end_sect = hndl.n_sects-1;
            } else {
                if (p_rng->sect>=1 && p_rng->sect<=hndl.n_sects) {
                    start_sect = p_rng->sect-1;
                    end_sect = start_sect;
                } else {
                    info_dbgprintf("Section number out of scope\n");
                    goto finish;
                }
            }

            for (DWORD sect_i=start_sect; sect_i<=end_sect; sect_i++) {
                scan_addr = RVA2ADDR(
                    get_32uint_le(&hndl.sectab[sect_i].VirtualAddress), mod_base);
                scan_len =
                    get_32uint_le(&hndl.sectab[sect_i].Misc.VirtualSize);

                if (scan_addr && scan_len)
                {
                    info_dbgprintf(
                        "Scanning section %d starting at: 0x%p, size: 0x%08X\n",
                        sect_i+1, scan_addr, scan_len);

                    /* continuous scan on error loop */
                    for (;;)
                    {
                        if (process_iat(&hndl, scan_addr, scan_len, &proc_len))
                        {
                            if (hndl.n_mods) {
                                /* IAT resolved; finish scanning */
                                goto break_sect_scan;
                            } else {
                                /* continue with the next section */
                                info_dbgprintf(
                                    "No imports found in section %d\n", sect_i+1);
                                break;
                            }
                        } else {
                            /* don't bother incomplete results */
                            free_imps_in_scan_imps_hndl(&hndl);

                            scan_addr += proc_len;
                            scan_len -= proc_len;

                            if (proc_len) {
                                info_dbgprintf("Resuming scanning from addr: "
                                    "0x%p, size: 0x%08X\n", scan_addr, scan_len);
                            } else {
                                err_dbgprintf(
                                    "Can not resume scanning from addr: 0x%p\n",
                                    scan_addr);
                                goto break_sect_scan;
                            }
                        }
                    }
                } else {
                    info_dbgprintf("Section %d is empty \n", p_rng->sect);
                }
            }
break_sect_scan:;
        } else
        {
            if (p_rng)
            {
                scan_addr = (p_rng->rng.is_rva ?
                    RVA2ADDR(p_rng->rng.rva, mod_base) : p_rng->rng.addr);
                if (!scan_addr || !p_rng->rng.len || p_rng->rng.len==(DWORD)-1)
                    goto finish;
                scan_len = p_rng->rng.len;
            } else {
                scan_addr = RVA2ADDR(iat_rva, mod_base);
                scan_len = iat_sz;
            }

            info_dbgprintf("IAT scanning starts at: 0x%p", scan_addr);
            if (scan_len!=(DWORD)-1)
                dbgprintf(", size constraint: 0x%04X\n", scan_len);
            else
                dbgprintf("\n");

            /* continuous scan on error loop */
            for (;;) {
                if (process_iat(&hndl, scan_addr, scan_len, &proc_len)) break;
                else
                {
                    /* don't bother incomplete results */
                    free_imps_in_scan_imps_hndl(&hndl);

                    scan_addr += proc_len;
                    scan_len -= proc_len;

                    if (proc_len) {
                        info_dbgprintf(
                            "Resuming scanning from addr: 0x%p, size: 0x%08X\n",
                            scan_addr, scan_len);
                    } else {
                        err_dbgprintf(
                            "Can not resume scanning from addr: 0x%p\n",
                            scan_addr);
                        break;
                    }
                }
            }
        }
    }

    if (!hndl.n_mods) {
        info_dbgprintf("No imports found\n");
        goto finish;
    }

    print_info_mod_dups(&hndl);

    if (flags & SCANIMPS_WRITE_CONF)
    {
        /* write imports spec to the conf. file */
        DWORD i, j;
        const imp_mod_desc_t *p_mod;
        const imp_proc_desc_t *p_proc;

        BOOL wcfg_ok=TRUE;
        char prm_name[32];
        char prm_val[max(MAX_PATH, MAX_SYM_NAME)+1];

        /* delete previous imports spec. */
        WritePrivateProfileString(PROP_SECT_IMPSPEC, NULL, NULL, PROP_FILE);

        for (p_mod=hndl.p_imp_mods, i=1;
            wcfg_ok && p_mod;
            p_mod=p_mod->next, i++)
        {
            if (*(p_mod->name)) {
                sprintf(prm_name, "%d", i);
                sprintf(prm_val, "%s", p_mod->name);
                wcfg_ok = wcfg_ok && WritePrivateProfileString(
                    PROP_SECT_IMPSPEC, prm_name, prm_val, PROP_FILE);
            }

            sprintf(prm_name, "%d.%s", i, PROP_IMPSPEC_IAT_RVA);
            sprintf(prm_val, "0x%08X", ADDR2RVA(p_mod->iat_addr, hndl.mod_base));
            wcfg_ok = wcfg_ok && WritePrivateProfileString(
                PROP_SECT_IMPSPEC, prm_name, prm_val, PROP_FILE);

            for (p_proc=p_mod->proc, j=1;
                wcfg_ok && p_proc;
                p_proc=p_proc->next, j++)
            {
                sprintf(prm_name, "%d.%d", i, j);

                if (strlen(p_proc->name)) sprintf(prm_val, "%s", p_proc->name);
                else sprintf(prm_val, "#0x%04X", p_proc->ord);

                wcfg_ok = wcfg_ok && WritePrivateProfileString(
                    PROP_SECT_IMPSPEC, prm_name, prm_val, PROP_FILE);
            }
        }

        if (wcfg_ok) {
            info_dbgprintf(
                "Resolved imports written to the config file; see its [%s] "
                "section.\n", PROP_SECT_IMPSPEC);
        } else {
            warn_dbgprintf(
                "Can't access the config file. Resolved imports are:\n");
            print_imp_spec(&hndl);
        }
    } else
    {
        info_dbgprintf("Resolved imports are:\n");
        print_imp_spec(&hndl);
    }

finish:
    if (b_fihndl) free_scan_imps_hndl(&hndl);
}

/* Search exports of the module with a name pointed by 'pc_mod_name', for the
   proc name with a name pointed by 'pc_proc_name'. If found TRUE is returned
   and the hint and ordinal for the proc are returned under 'p_out_hint' and
   'p_out_hint' respectively.
 */
static BOOL get_exp_proc_name_hint_ord(scan_imps_hndl_t *p_hndl,
    const char *pc_mod_name, const char *pc_proc_name, DWORD *p_out_hint,
    DWORD *p_out_ord, BOOL b_logs=FALSE)
{
    BOOL ret=FALSE;

    IDebugSymbols *DebugSymbols=NULL;
    if ((get_client()->QueryInterface(
        __uuidof(IDebugSymbols), (void **)&DebugSymbols)) != S_OK) goto finish;

    char mod_name[MAX_PATH+1];
    get_file_name(pc_mod_name, mod_name, sizeof(mod_name));

    ULONG64 mod_base;
    if (DebugSymbols->GetModuleByModuleName(mod_name, 0, NULL, &mod_base)!=S_OK)
    {
        if (b_logs) err_dbgprintf("Unable to find the module: %s\n", mod_name);
        goto finish;
    }

    /* check if the cache may be used */
    mod_exp_dir_t *p_ed = &p_hndl->ed_reslv;
    if (p_ed->mod_base != mod_base) {
        p_ed->mod_base = mod_base;
        if (!get_mod_exp_dir(p_ed, b_logs)) goto finish;
    }

    ret = get_name_hint_ord(p_ed, pc_proc_name, p_out_hint, p_out_ord);
    *p_out_ord += p_ed->ord_base;

finish:
    if (DebugSymbols) DebugSymbols->Release();
    return ret;
}

/* Read imports spec. config to populate the modules list. The 'p_iat_addr' and
   'p_iat_sz' will get the memory range of the IAT table. Returns TRUE on success.
 */
static BOOL read_imp_spec(scan_imps_hndl_t *p_hndl,
    ULONG64 *p_iat_addr, DWORD *p_iat_sz, BOOL b_imp_spec)
{
    BOOL ret=FALSE;

    IDebugSymbols *DebugSymbols=NULL;
    if ((get_client()->QueryInterface(
        __uuidof(IDebugSymbols), (void **)&DebugSymbols)) != S_OK) goto finish;

    char prm_name[32];
    char mod_name[MAX_PATH+1];
    char proc_name[MAX_SYM_NAME+1];

    /* used to calculate the IAT mem range */
    ULONG64 min_iat_addr=(ULONG64)-1, max_iat_addr=0;
    DWORD iat_elem_len = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
        sizeof(IMAGE_THUNK_DATA32) : sizeof(IMAGE_THUNK_DATA64));

    for (UINT lib_i=1;; lib_i++)
    {
        /* module name */
        sprintf(prm_name, "%d", lib_i);
        if (!GetPrivateProfileString(PROP_SECT_IMPSPEC,
            prm_name, "", mod_name, sizeof(mod_name), PROP_FILE))
        {
            if (!b_imp_spec) break;
            else *mod_name=0;
        }

        ULONG64 mod_base=0;
        if (!b_imp_spec)
        {
            char mod_name_ext[MAX_PATH+1];  /* module name w/o file extension */
            get_file_name(mod_name, mod_name_ext, sizeof(mod_name_ext));

            if (DebugSymbols->GetModuleByModuleName(
                mod_name_ext, 0, NULL, &mod_base)!=S_OK)
            {
                mod_base=0;
                warn_dbgprintf("Unable to find the module: %s; There will be "
                    "not possible to find hints of procs imported by names.\n",
                    mod_name);
            }
        }

        /* IAT rva */
        sprintf(prm_name, "%d.%s", lib_i, PROP_IMPSPEC_IAT_RVA);
        DWORD iat_rva =
            GetPrivateProfileInt(PROP_SECT_IMPSPEC, prm_name, -1, PROP_FILE);
        if (iat_rva==(DWORD)-1)
        {
            if (!b_imp_spec)
                warn_dbgprintf("Module no. %d in the [%s] section has not IAT "
                    "RVA specification. End of the modules list assumed.\n",
                    lib_i, PROP_SECT_IMPSPEC);
            break;
        }

        ULONG64 mod_iat_addr = RVA2ADDR(iat_rva, p_hndl->mod_base);
        if (mod_iat_addr < min_iat_addr) min_iat_addr=mod_iat_addr;

        UINT proc_i=1;
        for (proc_i;; proc_i++)
        {
            DWORD ord=0, hint=0;

            /* proc name */
            sprintf(prm_name, "%d.%d", lib_i, proc_i);
            if (!GetPrivateProfileString(PROP_SECT_IMPSPEC,
                prm_name, "", proc_name, sizeof(proc_name), PROP_FILE))
            {
                /* module w/o procs spec. */
                if (proc_i==1)
                    if (!add_imp_mod(p_hndl, mod_iat_addr, mod_base, mod_name))
                        goto finish;

                /* last proc of a module has been reached */
                mark_end_mod_imp_list(p_hndl);
                break;
            }

            if (proc_name[0]=='#') {
                ord = strtoul(proc_name+1, NULL, 0);
                proc_name[0] = 0;
            } else
            if (mod_base) {
                /* if possible try to resolve hint of the proc */
                get_exp_proc_name_hint_ord(
                    p_hndl, mod_name, proc_name, &hint, &ord);
            }

            /* add a new proc to the list of imported procs of the current module */
            if (!add_imp_mod_proc(p_hndl, ord, hint, proc_name,
                mod_iat_addr, mod_base, mod_name, TRUE)) goto finish;
        }

        ULONG64 mod_iat_end_addr = mod_iat_addr + proc_i*iat_elem_len;
        if (mod_iat_end_addr > max_iat_addr) max_iat_addr=mod_iat_end_addr;
    }

    print_info_mod_dups(p_hndl);

    /* calculate IAT's address range */
    *p_iat_addr = min_iat_addr;
    if (max_iat_addr > min_iat_addr)
        *p_iat_sz = (DWORD)(max_iat_addr-min_iat_addr);
    else
        *p_iat_sz = 0;

    ret=TRUE;
finish:
    if (DebugSymbols) DebugSymbols->Release();
    return ret;
}

/* Get IDT tab length (written under 'p_idt_sz') ILT tabs size ('p_ilts_sz'),
   hint/names tabs size, including modules names, rounded/un-rounded
   ('p_hns_modns_sz', 'p_hns_modns_nrnd_sz') and total modules names size,
   rounded/un-rounded ('p_modns_sz', 'p_modns_nrnd_sz').
 */
static void get_continuous_idt_sizes(const imp_mod_desc_t *p_imp_mods,
    DWORD n_mods, DWORD ilt_elem_len, DWORD *p_idt_sz, DWORD *p_ilts_sz,
    DWORD *p_hns_modns_sz, DWORD *p_hns_modns_nrnd_sz, DWORD *p_modns_sz,
    DWORD *p_modns_nrnd_sz)
{
    if (p_idt_sz) *p_idt_sz = (n_mods+1)*sizeof(IMAGE_IMPORT_DESCRIPTOR);

    if (p_ilts_sz) *p_ilts_sz = 0;
    if (p_hns_modns_sz) *p_hns_modns_sz = 0;
    if (p_hns_modns_nrnd_sz) *p_hns_modns_nrnd_sz = 0;
    if (p_modns_sz) *p_modns_sz = 0;
    if (p_modns_nrnd_sz) *p_modns_nrnd_sz = 0;

    for (const imp_mod_desc_t *p_mod=p_imp_mods; p_mod; p_mod=p_mod->next)
    {
        if (p_ilts_sz) *p_ilts_sz += (p_mod->n_procs+1)*ilt_elem_len;
        if (p_hns_modns_sz)
            *p_hns_modns_sz += p_mod->hnt_sz + RNDUP_W(strlen(p_mod->name)+1);
        if (p_hns_modns_nrnd_sz)
            *p_hns_modns_nrnd_sz += p_mod->hnt_nrnd_sz + strlen(p_mod->name)+1;
        if (p_modns_sz) *p_modns_sz += RNDUP_W(strlen(p_mod->name)+1);
        if (p_modns_nrnd_sz) *p_modns_nrnd_sz += strlen(p_mod->name)+1;
    }
}

/* Write fixed imports list (as specified by 'p_imp_mods') to the dumped file.
   The fix is provided by inspecting the IDT table (starts at rva 'idt_rva').
   The ILT tables are written in places pointed by inspected IDT. Hint/name
   table will be placed in rva pointed by 'hnt_rva'. Module names will be part
   of the hint/name table if 'modnms_rva' is -1 or will be placed starting at
   rva 'modnms_rva'. Returns TRUE if the patch has been written.
 */
static BOOL write_following_idt(const dump_pe_hndl_t *p_hndl,
    const imp_mod_desc_t *p_imp_mods, DWORD n_mods, DWORD idt_rva,
    DWORD hnt_rva, DWORD modnms_rva, DWORD flags, DWORD *p_idt_sz)
{
    BOOL ret=FALSE, f_err=FALSE;

    BOOL b_nms_nrnd = (flags&IDTSPEC_NO_PADD_NAMES)!=0;
    BOOL b_no_ilts = (flags&IDTSPEC_NO_ILTS)!=0;

    *p_idt_sz=0;

    DWORD ilt_elem_len = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
        sizeof(IMAGE_THUNK_DATA32) : sizeof(IMAGE_THUNK_DATA64));

    /* check passed rvas */
    DWORD hns_modns_sz, hns_modns_nrnd_sz, modns_sz, modns_nrnd_sz;
    get_continuous_idt_sizes(p_imp_mods, n_mods, ilt_elem_len, p_idt_sz, NULL,
        &hns_modns_sz, &hns_modns_nrnd_sz, &modns_sz, &modns_nrnd_sz);

    DWORD idt_rptr, hnt_rptr, modnms_rptr;
    if (!get_raw_ptr(p_hndl, idt_rva, &idt_rptr, NULL, NULL) || !idt_rptr)
    {
        err_dbgprintf(
            "IDT table outside PE sections raw image; rva: 0x%08X\n", idt_rva);
        goto finish;
    }

    DWORD hnt_n_raw_rem, hnt_sect_i, hns_sz;
    if (modnms_rva!=(DWORD)-1) {
        hns_sz = (b_nms_nrnd ?
            (hns_modns_nrnd_sz-modns_nrnd_sz) : (hns_modns_sz-modns_sz));
    } else {
        hns_sz = (b_nms_nrnd ? hns_modns_nrnd_sz : hns_modns_sz);
    }
    if (!get_raw_ptr(
        p_hndl, hnt_rva, &hnt_rptr, &hnt_n_raw_rem, &hnt_sect_i) || !hnt_rptr)
    {
        err_dbgprintf(
            "Hint/Name table outside PE sections raw image; rva: 0x%08X\n",
            hnt_rva);
        goto finish;
    }
    if (hnt_n_raw_rem < hns_sz) {
        err_dbgprintf("Not enough space in section %d to store Hint/Name "
            "table; rva: 0x%08X, size: 0x%04X\n", hnt_sect_i+1, hnt_rva, hns_sz);
        goto finish;
    }

    if (modnms_rva!=(DWORD)-1)
    {
        DWORD modnms_n_raw_rem, modnms_sect_i;
        DWORD modnms_sz = (b_nms_nrnd ? modns_nrnd_sz : modns_sz);
        if (!get_raw_ptr(p_hndl, modnms_rva,
            &modnms_rptr, &modnms_n_raw_rem, &modnms_sect_i) || !modnms_rptr)
        {
            err_dbgprintf(
                "Modules names table outside PE sections raw image; rva: 0x%08X\n",
                modnms_rva);
            goto finish;
        }
        if (modnms_n_raw_rem < modnms_sz)
        {
            err_dbgprintf(
                "Not enough space in section %d to store modules names table; "
                "rva: 0x%08X, size: 0x%04X\n", modnms_sect_i+1, modnms_rva,
                modnms_sz);
            goto finish;
        }
    }

    ULONG64 idt_addr = RVA2ADDR(idt_rva, p_hndl->mod_base);
    DWORD mod_name_rva = (modnms_rva!=(DWORD)-1 ? modnms_rva : hnt_rva);
    DWORD proc_name_rva = hnt_rva;

    info_dbgprintf(
        "Fixed imports patches will follow IDT table at 0x%p; rva: 0x%08X\n",
        idt_addr, idt_rva);

    /* follow IDT loop */
    IMAGE_IMPORT_DESCRIPTOR idt_ent;
    for (;; idt_addr+=sizeof(idt_ent))
    {
        /* get IDT elem */
        ULONG cb;
        if (!(read_memory(
            idt_addr, &idt_ent, sizeof(idt_ent), &cb) && cb==sizeof(idt_ent)))
            goto finish;

        /* zeroed entry marks end of the IDT table */
        if (!rmemchr(&idt_ent, 0, sizeof(idt_ent))) break;

        DWORD iat_rva = get_32uint_le(&idt_ent.FirstThunk);
        DWORD ilt_rva =
            (b_no_ilts ? iat_rva : get_32uint_le(&idt_ent.OriginalFirstThunk));

        /* find corresponding module's spec */
        const imp_mod_desc_t *p_mod;
        for (p_mod=p_imp_mods;
            p_mod && ADDR2RVA(p_mod->iat_addr, p_hndl->mod_base)!=iat_rva;
            p_mod=p_mod->next);

        if (!p_mod) {
            err_dbgprintf("IDT follow[0x%p]: can't find import spec. for the "
                "IAT; rva: 0x%08X\n", idt_addr, iat_rva);
            goto finish;
        }

        /*
            write ILT table
         */
        DWORD ilt_rptr, ilt_n_raw_rem, ilt_sect_i;
        if (!get_raw_ptr(
            p_hndl, ilt_rva, &ilt_rptr, &ilt_n_raw_rem, &ilt_sect_i) || !ilt_rptr)
        {
            err_dbgprintf("IDT follow[0x%p]: %s outside PE sections raw image; "
                "rva: 0x%08X\n", idt_addr, (b_no_ilts ? "IAT" : "ILT"), ilt_rva);
            goto finish;
        }

        DWORD ilt_sz = ilt_elem_len*(p_mod->n_procs+1);
        if (ilt_n_raw_rem < ilt_sz) {
            err_dbgprintf("IDT follow[0x%p]: not enough space in section %d "
                "to store %s; rva: 0x%08X, size: 0x%04X\n", idt_addr,
                ilt_sect_i+1, (b_no_ilts ? "ILT in IAT" : "ILT"),
                ilt_rva, ilt_sz);
            goto finish;
        }

        IMAGE_THUNK_DATA32 ilt32_ent;
        IMAGE_THUNK_DATA64 ilt64_ent;

        if (f_err=fseek(p_hndl->f_out, ilt_rptr, SEEK_SET)) goto finish;

        for (const imp_proc_desc_t *p_proc=p_mod->proc; p_proc; p_proc=p_proc->next)
        {
            size_t proc_name_len = strlen(p_proc->name);

            /* prepare ILT entry */
            if (p_hndl->nt_hdrs.pe_tpy==pe_32bit)
            {
                if (proc_name_len>0)
                    set_32uint_le(&ilt32_ent.u1.Function, proc_name_rva);
                else
                    set_32uint_le(&ilt32_ent.u1.Ordinal,
                        IMAGE_ORDINAL_FLAG32 | IMAGE_ORDINAL32(p_proc->ord));
            } else
            {
                if (proc_name_len>0)
                    set_64uint_le(&ilt64_ent.u1.Function, (ULONG64)proc_name_rva);
                else
                    set_64uint_le(&ilt64_ent.u1.Ordinal,
                        IMAGE_ORDINAL_FLAG64 | IMAGE_ORDINAL64(p_proc->ord));
            }

            if (f_err=(fwrite((p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
                (void*)&ilt32_ent : (void*)&ilt64_ent),
                ilt_elem_len, 1, p_hndl->f_out)!=1)) goto finish;

            if (proc_name_len>0)
                proc_name_rva +=
                    2+(b_nms_nrnd ? proc_name_len+1 : RNDUP_W(proc_name_len+1));
        }

        /* last ILT table entry is zero'ed */
        ilt32_ent.u1.Function=0; ilt64_ent.u1.Function=0;
        if (f_err=(fwrite((p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
            (void*)&ilt32_ent : (void*)&ilt64_ent),
            ilt_elem_len, 1, p_hndl->f_out)!=1)) goto finish;

        size_t mod_name_len = strlen(p_mod->name)+1;
        if (modnms_rva==(DWORD)-1)
            proc_name_rva += (b_nms_nrnd ? mod_name_len : RNDUP_W(mod_name_len));

        /*
            write hint/name table
         */
        if (f_err=fseek(p_hndl->f_out, hnt_rptr, SEEK_SET)) goto finish;

        size_t wrt_len;
        for (const imp_proc_desc_t *p_proc=p_mod->proc; p_proc; p_proc=p_proc->next)
        {
            size_t proc_name_len = strlen(p_proc->name);
            if (proc_name_len<=0) continue;
            wrt_len = (b_nms_nrnd ? proc_name_len+1 : RNDUP_W(proc_name_len+1));

            WORD w_hint;
            set_16uint_le(&w_hint, (WORD)p_proc->hint);
            if (f_err=(fwrite(&w_hint, sizeof(w_hint), 1, p_hndl->f_out)!=1))
                goto finish;

            if (f_err=(fwrite(p_proc->name, wrt_len, 1, p_hndl->f_out)!=1))
                goto finish;

            hnt_rptr += 2+wrt_len;
            if (modnms_rva==(DWORD)-1) mod_name_rva += 2+wrt_len;
        }

        /*
            write mod name
         */
        wrt_len = (b_nms_nrnd ? mod_name_len : RNDUP_W(mod_name_len));
        if (modnms_rva==(DWORD)-1) {
            /* ... in hint/name table */
            if (f_err=(fwrite(p_mod->name, wrt_len, 1, p_hndl->f_out)!=1))
                goto finish;
            hnt_rptr += wrt_len;
        } else {
            /* ... in a separate space */
            if (f_err=fseek(p_hndl->f_out, modnms_rptr, SEEK_SET))
                goto finish;
            if (f_err=(fwrite(p_mod->name, wrt_len, 1, p_hndl->f_out)!=1))
                goto finish;
            modnms_rptr += wrt_len;
        }

        /*
            update IDT elem
         */
        if (b_no_ilts) set_32uint_le(&idt_ent.OriginalFirstThunk, 0);
        set_32uint_le(&idt_ent.TimeDateStamp, 0);
        /* no forwarder chain */
        set_32uint_le(&idt_ent.ForwarderChain, (DWORD)-1);
        set_32uint_le(&idt_ent.Name, mod_name_rva);

        if (f_err=fseek(p_hndl->f_out, idt_rptr, SEEK_SET)) goto finish;
        if (f_err=(fwrite(&idt_ent, sizeof(idt_ent), 1, p_hndl->f_out)!=1))
            goto finish;
        idt_rptr += sizeof(idt_ent);

        mod_name_rva += wrt_len;
    }

    ret=TRUE;
finish:
    fflush(p_hndl->f_out);
    if (f_err) err_dbgprintf("File access error: %d\n", ferror(p_hndl->f_out));
    return ret;
}

/* Write fixed imports list (as specified by 'p_imp_mods') to the dumped file.
   The fix is provided as a continuous block constituting of:
   1. list of IDT table (IDT table element per importing module)
   2. list of ILT tables (ILT table per importing module)
   3. hint/name tables (single table per importing module) + importing module
      name at the end of each table

   The block starts at rva passed by 'idt_rva'. Returns TRUE if the patch has
   been written.
 */
static BOOL write_continuous_idt(const dump_pe_hndl_t *p_hndl,
    const imp_mod_desc_t *p_imp_mods, DWORD n_mods, DWORD idt_rva,
    DWORD flags, DWORD *p_idt_sz)
{
    BOOL ret=FALSE, f_err=FALSE;

    BOOL b_nms_nrnd = (flags&IDTSPEC_NO_PADD_NAMES)!=0;
    BOOL b_no_ilts = (flags&IDTSPEC_NO_ILTS)!=0;

    *p_idt_sz=0;

    DWORD idt_rptr, idt_n_raw_rem;
    if (!get_raw_ptr(
        p_hndl, idt_rva, &idt_rptr, &idt_n_raw_rem, NULL) || !idt_rptr)
    {
        err_dbgprintf(
            "IDT table outside PE sections raw image; rva: 0x%08X\n", idt_rva);
        goto finish;
    }

    /* set file ptr at the IDT */
    if (f_err=fseek(p_hndl->f_out, idt_rptr, SEEK_SET)) goto finish;

    DWORD ilt_elem_len = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
        sizeof(IMAGE_THUNK_DATA32) : sizeof(IMAGE_THUNK_DATA64));
    DWORD ilt_rva, hnt_rva, ilts_sz, hns_modns_sz, hns_modns_nrnd_sz, ptch_sz;

    get_continuous_idt_sizes(p_imp_mods, n_mods, ilt_elem_len, p_idt_sz,
        &ilts_sz, &hns_modns_sz, &hns_modns_nrnd_sz, NULL, NULL);

    if (b_no_ilts) {
        ilts_sz = 0;
        ilt_rva = 0;
        hnt_rva = idt_rva + *p_idt_sz;
    } else {
        ilt_rva = idt_rva + *p_idt_sz;
        hnt_rva = ilt_rva + ilts_sz;
    }
    ptch_sz =
        *p_idt_sz + ilts_sz + (b_nms_nrnd ? hns_modns_nrnd_sz : hns_modns_sz);

    info_dbgprintf("Continuous imports patch size: 0x%04X\n", ptch_sz);
    if (ptch_sz > idt_n_raw_rem)
    {
        err_dbgprintf("IDT continuous patch sticks out 0x%04X "
            "bytes beyond its section's raw size\n", ptch_sz-idt_n_raw_rem);
        goto finish;
    }

    /*
        write IDT elems
     */
    IMAGE_IMPORT_DESCRIPTOR idt_ent;
    DWORD mod_name_rva = hnt_rva;

    for (const imp_mod_desc_t *p_mod=p_imp_mods; p_mod; p_mod=p_mod->next)
    {
        mod_name_rva += (b_nms_nrnd ? p_mod->hnt_nrnd_sz : p_mod->hnt_sz);

        set_32uint_le(&idt_ent.OriginalFirstThunk, ilt_rva);
        set_32uint_le(&idt_ent.TimeDateStamp, 0);
        /* no forwarder chain */
        set_32uint_le(&idt_ent.ForwarderChain, (DWORD)-1);
        set_32uint_le(&idt_ent.Name, mod_name_rva);
        set_32uint_le(&idt_ent.FirstThunk,
            ADDR2RVA(p_mod->iat_addr, p_hndl->mod_base));

        if (f_err=(fwrite(&idt_ent, sizeof(idt_ent), 1, p_hndl->f_out)!=1))
            goto finish;

        if (!b_no_ilts) ilt_rva += (p_mod->n_procs+1)*ilt_elem_len;
        size_t mod_name_len = strlen(p_mod->name)+1;
        mod_name_rva += (b_nms_nrnd ? mod_name_len : RNDUP_W(mod_name_len));
    }

    /* last imp dir elem is zero'ed */
    memset(&idt_ent, 0, sizeof(idt_ent));
    if (f_err=(fwrite(&idt_ent, sizeof(idt_ent), 1, p_hndl->f_out)!=1))
        goto finish;

    /*
        write ILT tables
     */
    DWORD proc_name_rva = hnt_rva;

    for (const imp_mod_desc_t *p_mod=p_imp_mods; p_mod; p_mod=p_mod->next)
    {
        IMAGE_THUNK_DATA32 ilt32_ent;
        IMAGE_THUNK_DATA64 ilt64_ent;

        if (b_no_ilts)
        {
            /* for no ILTs conf. ILTs are written in places of IATs */
            DWORD iat_rptr, iat_n_raw_rem;
            DWORD iat_rva = ADDR2RVA(p_mod->iat_addr, p_hndl->mod_base);
            if (!get_raw_ptr(
                p_hndl, iat_rva, &iat_rptr, &iat_n_raw_rem, NULL) || !iat_rptr)
            {
                err_dbgprintf(
                    "IAT/ILT table outside PE sections raw image; rva: 0x%08X\n",
                    iat_rva);
                goto finish;
            }
            if (iat_n_raw_rem < (p_mod->n_procs+1)*ilt_elem_len) {
                err_dbgprintf("Unexpected end of the IAT table\n");
                goto finish;
            }
            if (f_err=fseek(p_hndl->f_out, iat_rptr, SEEK_SET)) goto finish;
        }

        for (const imp_proc_desc_t *p_proc=p_mod->proc; p_proc; p_proc=p_proc->next)
        {
            size_t proc_name_len = strlen(p_proc->name);

            /* prepare ILT entry */
            if (p_hndl->nt_hdrs.pe_tpy==pe_32bit)
            {
                if (proc_name_len>0) {
                    set_32uint_le(&ilt32_ent.u1.Function, proc_name_rva);
                } else {
                    set_32uint_le(&ilt32_ent.u1.Ordinal,
                        IMAGE_ORDINAL_FLAG32 | IMAGE_ORDINAL32(p_proc->ord));
                }
            } else
            {
                if (proc_name_len>0) {
                    set_64uint_le(&ilt64_ent.u1.Function, (ULONG64)proc_name_rva);
                } else {
                    set_64uint_le(&ilt64_ent.u1.Ordinal,
                        IMAGE_ORDINAL_FLAG64 | IMAGE_ORDINAL64(p_proc->ord));
                }
            }

            if (f_err=(fwrite((p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
                (void*)&ilt32_ent : (void*)&ilt64_ent),
                ilt_elem_len, 1, p_hndl->f_out)!=1)) goto finish;

            if (proc_name_len>0) {
                proc_name_rva +=
                    2+(b_nms_nrnd ? proc_name_len+1 : RNDUP_W(proc_name_len+1));
            }
        }

        /* last ILT table entry is zero'ed */
        ilt32_ent.u1.Function=0; ilt64_ent.u1.Function=0;
        if (f_err=(fwrite((p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
            (void*)&ilt32_ent : (void*)&ilt64_ent),
            ilt_elem_len, 1, p_hndl->f_out)!=1)) goto finish;

        size_t mod_name_len = strlen(p_mod->name)+1;
        proc_name_rva += (b_nms_nrnd ? mod_name_len : RNDUP_W(mod_name_len));
    }

    /*
        write hint/name tables & mod names
     */
    if (b_no_ilts) {
        /* set file ptr on the H/N table place */
        DWORD hnt_rptr;
        if (!get_raw_ptr(p_hndl, hnt_rva, &hnt_rptr, NULL, NULL) || !hnt_rptr)
        {
            err_dbgprintf(
                "Hint/Name table outside PE sections raw image; rva: 0x%08X\n",
                hnt_rva);
            goto finish;
        }
        if (f_err=fseek(p_hndl->f_out, hnt_rptr, SEEK_SET)) goto finish;
    }

    for (const imp_mod_desc_t *p_mod=p_imp_mods; p_mod; p_mod=p_mod->next)
    {
        size_t wrt_len;

        /* write hint/name table */
        for (const imp_proc_desc_t *p_proc=p_mod->proc; p_proc; p_proc=p_proc->next)
        {
            size_t proc_name_len = strlen(p_proc->name);
            if (proc_name_len<=0) continue;
            wrt_len = (b_nms_nrnd ? proc_name_len+1 : RNDUP_W(proc_name_len+1));

            WORD w_hint;
            set_16uint_le(&w_hint, (WORD)p_proc->hint);
            if (f_err=(fwrite(&w_hint, sizeof(w_hint), 1, p_hndl->f_out)!=1))
                goto finish;
            if (f_err=(fwrite(p_proc->name, wrt_len, 1, p_hndl->f_out)!=1))
                goto finish;
        }

        /* write mod name */
        size_t mod_name_len = strlen(p_mod->name)+1;
        wrt_len = (b_nms_nrnd ? mod_name_len : RNDUP_W(mod_name_len));
        if (f_err=(fwrite(p_mod->name, wrt_len, 1, p_hndl->f_out)!=1))
            goto finish;
    }

    ret=TRUE;

finish:
    fflush(p_hndl->f_out);
    if (f_err) err_dbgprintf("File access error: %d\n", ferror(p_hndl->f_out));

    return ret;
}

/* exported; see header for details */
BOOL patch_imports(const dump_pe_hndl_t *p_hndl)
{
    BOOL ret=FALSE, f_err=FALSE;

    /* read imports spec. */
    scan_imps_hndl_t sca_hndl;
    init_scan_imps_hndl(&sca_hndl, p_hndl);

    ULONG64 iat_addr;
    DWORD iat_sz, idt_sz;
    if (!read_imp_spec(&sca_hndl, &iat_addr, &iat_sz, FALSE)) goto err;
    if (!sca_hndl.n_mods) goto no_err;

    /* get imports related dirs */
    IMAGE_DATA_DIRECTORY *p_dd_idt, *p_dd_iat;
    if (!get_data_dir(&p_hndl->nt_hdrs,
        IMAGE_DIRECTORY_ENTRY_IMPORT, &p_dd_idt, FALSE)) goto no_err;
    if (!get_data_dir(&p_hndl->nt_hdrs,
        IMAGE_DIRECTORY_ENTRY_IAT, &p_dd_iat, FALSE)) p_dd_iat=NULL;

    char prm_val[32];
    DWORD idt_rva, iat_rva;

    /* establish IDT as the point of the patch */
    if ((GetPrivateProfileString(PROP_SECT_DIRS,
        PROP_DIRS_IDT_RVA, "", prm_val, sizeof(prm_val), PROP_FILE)>0) &&
        !strcmpi(prm_val, IDT_AFTER_IAT))
    {
        idt_rva = ADDR2RVA(iat_addr, p_hndl->mod_base) + iat_sz;
        info_dbgprintf("%s/%s = 0x%08X; after IAT\n",
            PROP_SECT_DIRS, PROP_DIRS_IDT_RVA, idt_rva);
    } else {
        idt_rva = get_32uint_le(&p_dd_idt->VirtualAddress);
    }
    if (!idt_rva) goto no_err;

    DWORD idt_flags=0;
    if (GetPrivateProfileInt(
        PROP_SECT_IMPFIX, PROP_IMPFIX_NO_PADD_NAMES, 0, PROP_FILE))
    {
        idt_flags |= IDTSPEC_NO_PADD_NAMES;
        info_dbgprintf("Names in fixed imports will not be padded\n");
    }
    if (GetPrivateProfileInt(
        PROP_SECT_IMPFIX, PROP_IMPFIX_NO_ILTS, 0, PROP_FILE))
    {
        idt_flags |= IDTSPEC_NO_ILTS;
        info_dbgprintf("ILT tables will not be written to the imports dir\n");
    }

    DWORD hnt_rva, modnms_rva;
    hnt_rva = GetPrivateProfileInt(
        PROP_SECT_IMPFIX, PROP_IMPFIX_HN_TAB_RVA, -1, PROP_FILE);
    modnms_rva = GetPrivateProfileInt(
        PROP_SECT_IMPFIX, PROP_IMPFIX_NAME_TAB_RVA, -1, PROP_FILE);

    /* patch imports */
    if (hnt_rva!=(DWORD)-1) {
        if (!write_following_idt(p_hndl, sca_hndl.p_imp_mods, sca_hndl.n_mods,
            idt_rva, hnt_rva, modnms_rva, idt_flags, &idt_sz)) goto err;
    } else {
        if (!write_continuous_idt(p_hndl, sca_hndl.p_imp_mods,
            sca_hndl.n_mods, idt_rva, idt_flags, &idt_sz)) goto err;
    }

    /* finally update the IAT & IDT dirs */
    DWORD dirs_rptr = get_32uint_le(&p_hndl->dos_hdr.e_lfanew) +
        (UINT8*)(p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
        &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.DataDirectory[0] :
        &p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.DataDirectory[0]) -
        (UINT8*)&(p_hndl->nt_hdrs.hdr);

    /* IDT dir */
    DWORD dd_idt_rptr =
        dirs_rptr + IMAGE_DIRECTORY_ENTRY_IMPORT*sizeof(IMAGE_DATA_DIRECTORY);

    set_32uint_le(&p_dd_idt->VirtualAddress, idt_rva);
    set_32uint_le(&p_dd_idt->Size, idt_sz);

    if (!fseek(p_hndl->f_out, dd_idt_rptr, SEEK_SET) &&
        fwrite(p_dd_idt, 1, sizeof(*p_dd_idt), p_hndl->f_out)==sizeof(*p_dd_idt))
    {
        info_dbgprintf(
            "IDT has been patched; IDT directory rva: 0x%08X, size: 0x%04X\n",
            idt_rva, idt_sz);
    } else
    { f_err=TRUE; goto err; }

    /* IAT dir is updated only if has not been already configured */
    if ((GetPrivateProfileInt(
            PROP_SECT_DIRS, PROP_DIRS_IAT_RVA, -1, PROP_FILE)==(DWORD)-1) &&
        (GetPrivateProfileInt(
            PROP_SECT_DIRS, PROP_DIRS_IAT_SZ, -1, PROP_FILE)==(DWORD)-1) &&
        p_dd_iat)
    {
        DWORD dd_iat_rptr =
            dirs_rptr + IMAGE_DIRECTORY_ENTRY_IAT*sizeof(IMAGE_DATA_DIRECTORY);
        iat_rva = ADDR2RVA(iat_addr, p_hndl->mod_base);

        set_32uint_le(&p_dd_iat->VirtualAddress, iat_rva);
        set_32uint_le(&p_dd_iat->Size, iat_sz);

        if (!fseek(p_hndl->f_out, dd_iat_rptr, SEEK_SET) && fwrite(
            p_dd_iat, 1, sizeof(*p_dd_iat), p_hndl->f_out)==sizeof(*p_dd_iat))
        {
            info_dbgprintf(
                "IAT directory updated; rva: 0x%08X, size: 0x%04X\n",
                iat_rva, iat_sz);
        } else
        { f_err=TRUE; goto err; }
    }

no_err:
    ret=TRUE;
err:
    if (f_err) err_dbgprintf("File access error: %d\n", ferror(p_hndl->f_out));

    free_scan_imps_hndl(&sca_hndl);
    return ret;
}

/* exported; see header for details */
BOOL fix_iat(const dump_pe_hndl_t *p_hndl)
{
    BOOL ret=FALSE, b_ferr=FALSE;

    if (GetPrivateProfileInt(
        PROP_SECT_IMPFIX, PROP_IMPFIX_NO_ILTS, 0, PROP_FILE))
    {
        /* ILTs are already set on the IATs places; there is nothing to do */
        goto no_err;
    }

    /* check the IDT table consistency */
    IMAGE_DATA_DIRECTORY *p_dd_idt;
    if (!get_data_dir(&p_hndl->nt_hdrs,
        IMAGE_DIRECTORY_ENTRY_IMPORT, &p_dd_idt, FALSE)) goto no_err;

    DWORD idt_rva = get_32uint_le(&p_dd_idt->VirtualAddress);
    DWORD idt_sz = get_32uint_le(&p_dd_idt->Size);
    if (!idt_rva || !idt_sz) goto no_err;

    DWORD idt_rptr, idt_n_raw_rem, sect_i;
    if (!get_raw_ptr(
        p_hndl, idt_rva, &idt_rptr, &idt_n_raw_rem, &sect_i) || !idt_rptr)
    {
        err_dbgprintf(
            "IDT table outside PE sections raw image; rva: 0x%08X\n", idt_rva);
        goto err;
    }

    IMAGE_IMPORT_DESCRIPTOR idt_ent;
    DWORD imp_elem_len = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
        sizeof(IMAGE_THUNK_DATA32) : sizeof(IMAGE_THUNK_DATA64));

    for (;; idt_rptr+=sizeof(idt_ent), idt_n_raw_rem-=sizeof(idt_ent))
    {
        if (idt_n_raw_rem<sizeof(idt_ent)) {
            err_dbgprintf("Unexpected end of the IDT table\n");
            goto err;
        }

        if (b_ferr=fseek(p_hndl->f_out, idt_rptr, SEEK_SET)) goto err;
        if (b_ferr=(fread(
            &idt_ent, 1, sizeof(idt_ent), p_hndl->f_out)!=sizeof(idt_ent)))
            goto err;

        /* last zeroed block marks an end of the IDT */
        if (!rmemchr(&idt_ent, 0, sizeof(idt_ent))) break;

        /* write zeroed idt_ent.TimeDateStamp */
        DWORD ts=0;
        DWORD idt_ts_rptr =
            idt_rptr+((UINT8*)(&idt_ent.TimeDateStamp)-(UINT8*)(&idt_ent));

        if (b_ferr=fseek(p_hndl->f_out, idt_ts_rptr, SEEK_SET)) goto err;
        if (b_ferr=(fwrite(&ts, 1, sizeof(ts), p_hndl->f_out)!=sizeof(ts)))
            goto err;

        DWORD iat_rptr, iat_n_raw_rem;
        DWORD iat_rva = get_32uint_le(&idt_ent.FirstThunk);
        if (!get_raw_ptr(
            p_hndl, iat_rva, &iat_rptr, &iat_n_raw_rem, &sect_i) || !iat_rptr)
        {
            err_dbgprintf(
                "IAT table outside PE sections raw image; rva: 0x%08X\n", iat_rva);
            goto err;
        }

        DWORD ilt_rptr, ilt_n_raw_rem;
        DWORD ilt_rva = get_32uint_le(&idt_ent.OriginalFirstThunk);
        if (!get_raw_ptr(
            p_hndl, ilt_rva, &ilt_rptr, &ilt_n_raw_rem, &sect_i) || !ilt_rptr)
        {
            err_dbgprintf(
                "ILT table outside PE sections raw image; rva: 0x%08X\n", ilt_rva);
            goto err;
        }

        /* copy ILT to IAT table loop */
        for (;; iat_rptr+=imp_elem_len, iat_n_raw_rem-=imp_elem_len,
            ilt_rptr+=imp_elem_len, ilt_n_raw_rem-=imp_elem_len)
        {
            if (iat_n_raw_rem<imp_elem_len) {
                err_dbgprintf("Unexpected end of the IAT table\n");
                goto err;
            }
            if (ilt_n_raw_rem<imp_elem_len) {
                err_dbgprintf("Unexpected end of the ILT table\n");
                goto err;
            }

            IMAGE_THUNK_DATA32 elem32;
            IMAGE_THUNK_DATA64 elem64;
            void *p_elem = (p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
                (void*)&elem32 : (void*)&elem64);

            if (b_ferr=fseek(p_hndl->f_out, ilt_rptr, SEEK_SET)) goto err;
            if (b_ferr=(fread(
                p_elem, 1, imp_elem_len, p_hndl->f_out)!=imp_elem_len)) goto err;

            if (b_ferr=fseek(p_hndl->f_out, iat_rptr, SEEK_SET)) goto err;
            if (b_ferr=(fwrite(
                p_elem, 1, imp_elem_len, p_hndl->f_out)!=imp_elem_len)) goto err;

            /* last zero entry marks end of the table */
            if (!rmemchr(p_elem, 0, imp_elem_len)) break;
        }
    }

    info_dbgprintf("IAT table successfully fixed\n");

no_err:
    ret=TRUE;
err:
    if (b_ferr) err_dbgprintf("Dump file access error\n");
    return ret;
}

/* Bind status routine */
static BOOL __stdcall bind_status(IMAGEHLP_STATUS_REASON Reason,
    PCSTR ImageName, PCSTR DllName, ULONG_PTR Va, ULONG_PTR Parameter)
{
    switch (Reason)
    {
    case BindImageComplete:
        info_dbgprintf("Bound imports:\n");

        PIMAGE_BOUND_IMPORT_DESCRIPTOR imports = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)Va;
        PIMAGE_BOUND_IMPORT_DESCRIPTOR import = imports;

        while (import->OffsetModuleName)
        {
            dbgprintf(" Import %s, Timestamp: 0x%08X",
                (LPSTR)imports + import->OffsetModuleName, import->TimeDateStamp);

            if (import->NumberOfModuleForwarderRefs > 0) {
                dbgprintf(" with %d forwarder(s)",
                    import->NumberOfModuleForwarderRefs);
            }
            dbgprintf("\n" );

            PIMAGE_BOUND_FORWARDER_REF forwarder =
                (PIMAGE_BOUND_FORWARDER_REF)(import+1);

            for (DWORD i=0; i < import->NumberOfModuleForwarderRefs; i++)
            {
                dbgprintf("  Forwarder %s, Timestamp: 0x%08X\n",
                    (LPSTR)imports + forwarder->OffsetModuleName,
                    forwarder->TimeDateStamp);

                forwarder++;
            }
            import = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)forwarder;
        }
        break;
    }
    return TRUE;
}

/* exported; see header for details */
BOOL bind_imports(const char *pc_pe_file)
{
    typedef
    BOOL
    (__stdcall *PBIND_IMAGE_EX)(
        DWORD Flags,
        PCSTR ImageName,
        PCSTR DllPath,
        PCSTR SymbolPath,
        PIMAGEHLP_STATUS_ROUTINE StatusRoutine);

    static const char *lib_name = "imagehlp.dll";
    static const char *bind_func_name = "BindImageEx";

    BOOL ret=FALSE;

    HMODULE h_mod = LoadLibrary(lib_name);
    if (!h_mod) {
        err_dbgprintf("Unable to load %s library\n", lib_name);
        goto finish;
    }

    PBIND_IMAGE_EX bind_img =
        (PBIND_IMAGE_EX)GetProcAddress(h_mod, bind_func_name);
    if (!bind_img)
    {
        err_dbgprintf(
            "Unable to get %s proc in %s library\n", bind_func_name, lib_name);
        goto finish;
    }

    PIMAGEHLP_STATUS_ROUTINE stat_routine = bind_status;

    if (!bind_img(BIND_ALL_IMAGES, pc_pe_file, NULL, NULL, stat_routine)) {
        err_dbgprintf("Bind error: 0x%08X\n", GetLastError());
        goto finish;
    }

    info_dbgprintf("Imports have been bound\n");
    ret=TRUE;
finish:
    if (h_mod) FreeLibrary(h_mod);
    return ret;
}

/* exported; see header for details */
void print_imports(ULONG64 mod_base, const rng_spec_t *p_rng, DWORD flags)
{
    prnt_dir_hndl_t hndl;
    if (!init_prnt_dir_hndl(&hndl, mod_base, IMAGE_DIRECTORY_ENTRY_IMPORT, p_rng))
        goto finish;

    /* print header */
    if (!hndl.dir_addr || (!p_rng && !hndl.dir_sz)) {
        info_dbgprintf("No imports in this module!\n");
        goto finish;
    } else
        info_dbgprintf("IDT table at: 0x%p\n", hndl.dir_addr);

    if (flags&PRNTIMP_IMPSPEC)
        dbgprintf("\n[%s]\n", PROP_SECT_IMPSPEC);
    else
        info_dbgprintf("RVA provided in [], 'h:' denotes hints\n\n");

    DWORD iat_elem_len = (hndl.nt_hdrs.pe_tpy==pe_32bit ?
        sizeof(IMAGE_THUNK_DATA32) : sizeof(IMAGE_THUNK_DATA64));

    UINT lib_i=1;
    IMAGE_IMPORT_DESCRIPTOR idt_ent;
    DWORD len_cnstr = (p_rng ? p_rng->rng.len : hndl.dir_sz);

    /* go through IDT elems */
    for (ULONG64 idt_elem_addr=hndl.dir_addr;;
        idt_elem_addr+=sizeof(idt_ent),
        len_cnstr-=(len_cnstr!=(DWORD)-1 ? sizeof(idt_ent) : 0), lib_i++)
    {
        if (len_cnstr!=(DWORD)-1 && len_cnstr<sizeof(idt_ent)) break;

        ULONG cb;
        if (!(read_memory(idt_elem_addr, &idt_ent, sizeof(idt_ent), &cb) &&
            cb==sizeof(idt_ent))) break;

        /* zeroed entry marks end of the IDT table */
        if (!rmemchr(&idt_ent, 0, sizeof(idt_ent))) break;

        DWORD ilt_rva = get_32uint_le(&idt_ent.OriginalFirstThunk);
        ULONG64 ilt_addr = RVA2ADDR(ilt_rva, mod_base);

        DWORD timestamp = get_32uint_le(&idt_ent.TimeDateStamp);

        DWORD name_rva = get_32uint_le(&idt_ent.Name);
        ULONG64 name_addr = RVA2ADDR(name_rva, mod_base);

        DWORD iat_rva = get_32uint_le(&idt_ent.FirstThunk);
        ULONG64 iat_addr = RVA2ADDR(iat_rva, mod_base);

        char mod_name[MAX_PATH+1];
        if (string_cpy_lt(mod_name, name_addr, sizeof(mod_name))) {
            if (flags&PRNTIMP_IMPSPEC) dbgprintf("%d = %s\n", lib_i, mod_name);
        } else {
            if (flags&PRNTIMP_IMPSPEC) {
                err_dbgprintf(
                    "Can not retrieve module name from 0x%p\n", name_addr);
                goto finish;
            } else strcpy(mod_name, "???");
        }

        if (flags&PRNTIMP_IMPSPEC) {
            dbgprintf("%d.%s = 0x%08X\n", lib_i, PROP_IMPSPEC_IAT_RVA, iat_rva);
        } else {
            dbgprintf("0x%p[0x%08X] %s IDT Entry:\n",
                idt_elem_addr, ADDR2RVA(idt_elem_addr, mod_base), mod_name);
            dbgprintf("  ILT at:          0x%p[0x%08X]\n", ilt_addr, ilt_rva);
            dbgprintf("  Timestamp:       0x%08X   ; %s\n", timestamp,
                (!timestamp ? "not bound" :
                (timestamp==(DWORD)-1 ? "new-type bind" : "old-type bind")));
            dbgprintf("  Forwarder chain: 0x%08X\n",
                get_32uint_le(&idt_ent.ForwarderChain));
            dbgprintf("  Module name at:  0x%p[0x%08X]\n", name_addr, name_rva);
            dbgprintf("  IAT at:          0x%p[0x%08X]\n", iat_addr, iat_rva);
            dbgprintf(" Imports:\n");
        }

        if (ilt_addr)
        {
            UINT proc_i=1;

            /* go through ILT elems */
            for (DWORD iat_off=0;; iat_off+=iat_elem_len, proc_i++)
            {
                /* max size to fit 32/64 PE */
                BOOL is_ord;
                ULONG64 ilt_ent;
                ULONG64 proc_addr;

                if (!(read_memory(ilt_addr+iat_off, &ilt_ent, iat_elem_len, &cb)
                    && cb==iat_elem_len)) break;

                /* zeroed entry marks end of the table */
                if (!rmemchr(&ilt_ent, 0, iat_elem_len)) break;

                if (hndl.nt_hdrs.pe_tpy==pe_32bit) {
                    ilt_ent = get_32uint_le(&ilt_ent);
                    is_ord = IMAGE_SNAP_BY_ORDINAL32(ilt_ent);
                } else {
                    ilt_ent = get_64uint_le(&ilt_ent);
                    is_ord = IMAGE_SNAP_BY_ORDINAL64(ilt_ent);
                }

                if (!(flags&PRNTIMP_IMPSPEC))
                {
                    if (read_memory(iat_addr+iat_off, &proc_addr, iat_elem_len, &cb)
                        && cb==iat_elem_len)
                    {
                        proc_addr = (hndl.nt_hdrs.pe_tpy==pe_32bit ?
                            DEBUG_EXTEND64(get_32uint_le(&proc_addr)) :
                            get_64uint_le(&proc_addr));
                    } else
                        proc_addr=(ULONG64)-1;

                    if (proc_addr!=(ULONG64)-1) dbgprintf("  0x%p: ", proc_addr);
                    else dbgprintf("  ???: ");
                }

                if (!is_ord)
                {
                    DWORD hnt_rva = ilt_ent;
                    ULONG64 hnt_addr = RVA2ADDR(hnt_rva, mod_base);

                    if (!(flags&PRNTIMP_IMPSPEC))
                        dbgprintf("0x%p[0x%08X]", hnt_addr, hnt_rva);

                    WORD hint;
                    char proc_name[MAX_SYM_NAME+1];

                    if (!(read_memory(hnt_addr, &hint, sizeof(hint), &cb) &&
                        cb==sizeof(hint))) hint=0;
                    hnt_addr += sizeof(hint);

                    if (!string_cpy_lt(proc_name, hnt_addr, sizeof(proc_name)))
                    {
                        if (flags&PRNTIMP_IMPSPEC) {
                            err_dbgprintf(
                                "Can not retrieve proc name from 0x%p\n", hnt_addr);
                            goto finish;
                        } else
                            strcpy(proc_name, "???");
                    }

                    if (flags&PRNTIMP_IMPSPEC)
                        dbgprintf("%d.%d = %s\n", lib_i, proc_i, proc_name);
                    else
                        dbgprintf(" h:0x%04X %s", hint, proc_name);
                } else {
                    UINT ord = ilt_ent&0xffff;

                    if (flags&PRNTIMP_IMPSPEC)
                        dbgprintf("%d.%d = #0x%04X\n", lib_i, proc_i, ord);
                    else
                        dbgprintf("Ordinal #0x%04X", ord);
                }
                if (!(flags&PRNTIMP_IMPSPEC)) dbgprintf("\n");
            }
        } else
        if (!(flags&PRNTIMP_IMPSPEC))
        {
            /* go through IAT elems */
            for (DWORD iat_off=0;; iat_off+=iat_elem_len)
            {
                ULONG64 proc_addr;

                if (!(read_memory(iat_addr+iat_off, &proc_addr, iat_elem_len, &cb)
                    && cb==iat_elem_len)) break;

                proc_addr = (hndl.nt_hdrs.pe_tpy==pe_32bit ?
                    DEBUG_EXTEND64(get_32uint_le(&proc_addr)) :
                    get_64uint_le(&proc_addr));

                /* zeroed address marks end of the table */
                if (!proc_addr) break;

                dbgprintf("  0x%p: ???\n", proc_addr);
            }
        }
    }

finish:
    return;
}

/* exported; see header for details */
void print_exports(ULONG64 mod_base, const rng_spec_t *p_rng)
{
    WORD ords_tab[1000];    /* default ords tab */
    WORD *p_ords_tab = &ords_tab[0];

    prnt_dir_hndl_t hndl;
    if (!init_prnt_dir_hndl(&hndl, mod_base, IMAGE_DIRECTORY_ENTRY_EXPORT, p_rng))
        goto finish;

    /* print header */
    if (!hndl.dir_addr || (!p_rng && !hndl.dir_sz)) {
        info_dbgprintf("No exports in this module!\n");
        goto finish;
    } else
        info_dbgprintf("Export Directory at: 0x%p\n", hndl.dir_addr);

    info_dbgprintf(
        "RVA provided in [], '#' precedes ordinals, 'h:' denotes hints\n");
    if (!hndl.dir_sz) info_dbgprintf("Forwarder exports will not be shown\n");
    dbgprintf("\n");

    ULONG cb;
    IMAGE_EXPORT_DIRECTORY exp_dir;

    /* retrieve export table info */
    if (!(read_memory(hndl.dir_addr, &exp_dir, sizeof(exp_dir), &cb) &&
        cb==sizeof(exp_dir))) goto finish;

    DWORD name_rva = get_32uint_le(&exp_dir.Name);
    ULONG64 name_addr = RVA2ADDR(name_rva, mod_base);

    char mod_name[MAX_PATH+1];
    if (!string_cpy_lt(mod_name, name_addr, sizeof(mod_name)))
        strcpy(mod_name, "???");

    DWORD ord_base = get_32uint_le(&exp_dir.Base);
    DWORD n_faddrs = get_32uint_le(&exp_dir.NumberOfFunctions);
    DWORD n_fnames = get_32uint_le(&exp_dir.NumberOfNames);

    DWORD faddrs_rva = get_32uint_le(&exp_dir.AddressOfFunctions);
    ULONG64 faddrs_addr = RVA2ADDR(faddrs_rva, mod_base);

    DWORD fnames_rva = get_32uint_le(&exp_dir.AddressOfNames);
    ULONG64 fnames_addr = RVA2ADDR(fnames_rva, mod_base);

    DWORD fords_rva = get_32uint_le(&exp_dir.AddressOfNameOrdinals);
    ULONG64 fords_addr = RVA2ADDR(fords_rva, mod_base);

    dbgprintf("0x%p[0x%08X] %s Export Directory:\n",
        hndl.dir_addr, ADDR2RVA(hndl.dir_addr, mod_base), mod_name);
    dbgprintf("  Characteristics:      0x%08X\n",
        get_32uint_le(&exp_dir.Characteristics));
    dbgprintf("  Timestamp:            0x%08X\n",
        get_32uint_le(&exp_dir.TimeDateStamp));
    dbgprintf("  Major version:        0x%04X\n",
        get_16uint_le(&exp_dir.MajorVersion));
    dbgprintf("  Minor version:        0x%04X\n",
        get_16uint_le(&exp_dir.MinorVersion));
    dbgprintf("  Module name at:       0x%p[0x%08X]\n", name_addr, name_rva);
    dbgprintf("  Ordinal base:         0x%08X\n", ord_base);
    dbgprintf("  Address tab. entries: 0x%08X\n", n_faddrs);
    dbgprintf("  Number of name ptrs:  0x%08X\n", n_fnames);
    dbgprintf("  Export addr table at: 0x%p[0x%08X]\n", faddrs_addr, faddrs_rva);
    dbgprintf("  Name ptrs table at:   0x%p[0x%08X]\n", fnames_addr, fnames_rva);
    dbgprintf("  Ordinals table at:    0x%p[0x%08X]\n", fords_addr, fords_rva);
    dbgprintf(" Exports:\n");

    if (n_fnames > sizeof(ords_tab)/sizeof(ords_tab[0]))
        p_ords_tab=(WORD*)malloc(n_fnames*sizeof(*p_ords_tab));
    if (!p_ords_tab) goto finish;

    /* read ords table */
    cb=0;
    read_memory(fords_addr, p_ords_tab, n_fnames*sizeof(*p_ords_tab), &cb);
    DWORD rd_n_fnames = cb/sizeof(*p_ords_tab);
    if (rd_n_fnames<n_fnames) {
        warn_dbgprintf("Read 0x%04X of 0x%04X from the ordinals table elements.\n",
            rd_n_fnames, n_fnames);
    }

    /* go through EAT table */
    DWORD exp_rva;
    ULONG64 eat_ent_addr=faddrs_addr;
    for (DWORD eat_i=0; eat_i<n_faddrs; eat_i++, eat_ent_addr+=sizeof(exp_rva))
    {
        ULONG64 exp_addr=0;

        if (read_memory(eat_ent_addr, &exp_rva, sizeof(exp_rva), &cb) &&
            cb==sizeof(exp_rva))
        {
            exp_rva = get_32uint_le(&exp_rva);
            exp_addr = RVA2ADDR(exp_rva, mod_base);
            dbgprintf("  0x%p[0x%08X]:", exp_addr, exp_rva);
        } else
            dbgprintf("  ???:");

        dbgprintf(" #0x%04X", eat_i+ord_base);

        /* search ordinals table for the EAT index */
        DWORD hint;
        for (hint=0; hint<rd_n_fnames; hint++) {
            if (eat_i==p_ords_tab[hint])
            {
                /* named import */
                dbgprintf(" h:0x%04X", hint);

                DWORD func_rva;
                if (read_memory(fnames_addr+hint*sizeof(func_rva), &func_rva,
                    sizeof(func_rva), &cb) && cb==sizeof(func_rva))
                {
                    char proc_name[MAX_SYM_NAME+1];
                    if (!string_cpy_lt(proc_name, RVA2ADDR(func_rva, mod_base),
                        sizeof(proc_name))) strcpy(proc_name, "???");

                    dbgprintf(" 0x%p[0x%08X] %s", RVA2ADDR(func_rva, mod_base),
                        func_rva, proc_name);
                } else
                    dbgprintf(" ???");
                break;
            }
        }

        /* check for forwarded export */
        if (hndl.dir_sz &&
            hndl.dir_addr<=exp_addr &&
            exp_addr<hndl.dir_addr+hndl.dir_sz)
        {
            char frwrd[MAX_PATH+MAX_SYM_NAME+4];
            if (!string_cpy_lt(frwrd, exp_addr, sizeof(frwrd)))
                strcpy(frwrd, "???");

            dbgprintf(" -> %s", frwrd);
        }
        dbgprintf("\n");
    }

finish:
    if (p_ords_tab && p_ords_tab!=&ords_tab[0]) free(p_ords_tab);
    return;
}

/* exported; see header for details */
void print_bound_imps(ULONG64 mod_base, const rng_spec_t *p_rng)
{
    prnt_dir_hndl_t hndl;
    if (!init_prnt_dir_hndl(
        &hndl, mod_base, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, p_rng)) goto finish;

    /* print header */
    if (!hndl.dir_addr || (!p_rng && !hndl.dir_sz)) {
        info_dbgprintf("No bound imports descr. in this module!\n");
        goto finish;
    } else
        info_dbgprintf("Bound Imports Directory (BID) at: 0x%p\n", hndl.dir_addr);

    info_dbgprintf("RVA provided in []\n\n");

    UINT frwrd_n=0;
    DWORD off=0;
    IMAGE_BOUND_IMPORT_DESCRIPTOR bid_ent;
    DWORD len_cnstr = (p_rng ? p_rng->rng.len : hndl.dir_sz);

    for (;; off+=sizeof(bid_ent),
        len_cnstr-=(len_cnstr!=(DWORD)-1 ? sizeof(bid_ent) : 0))
    {
        if (len_cnstr!=(DWORD)-1 && len_cnstr<sizeof(bid_ent)) break;

        ULONG cb;
        if (!(read_memory(hndl.dir_addr+off, &bid_ent, sizeof(bid_ent), &cb) &&
            cb==sizeof(bid_ent))) goto finish;

        /* zeroed entry marks end of the BID table */
        if (!rmemchr(&bid_ent, 0, sizeof(bid_ent))) break;

        DWORD name_off = get_16uint_le(&bid_ent.OffsetModuleName);
        ULONG64 name_addr = hndl.dir_addr+name_off;

        char mod_name[MAX_PATH+1];
        if (!string_cpy_lt(mod_name, name_addr, sizeof(mod_name)))
            strcpy(mod_name, "???");

        const char *spc = (frwrd_n ? "  " : "");
        dbgprintf("%s0x%p[0x%08X] %s BID Entry:\n", spc, hndl.dir_addr+off,
            ADDR2RVA(hndl.dir_addr+off, mod_base), mod_name);
        dbgprintf("%s  Timestamp:            0x%08X\n",
            spc, get_32uint_le(&bid_ent.TimeDateStamp));
        dbgprintf("%s  Module name at:       0x%p+0x%04X\n",
            spc, hndl.dir_addr, name_off);

        if (!frwrd_n) {
            if (frwrd_n=get_16uint_le(&bid_ent.NumberOfModuleForwarderRefs))
                dbgprintf("%s Forwarders [0x%04X]:\n", spc, frwrd_n);
        } else {
            dbgprintf("%s  Reserved:             0x%04X\n",
                spc, get_16uint_le(&bid_ent.NumberOfModuleForwarderRefs));
            frwrd_n--;
        }
    }

finish:
    return;
}

/* exported; see header for details */
void print_delay_imps(ULONG64 mod_base, const rng_spec_t *p_rng)
{
    prnt_dir_hndl_t hndl;
    if (!init_prnt_dir_hndl(
        &hndl, mod_base, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, p_rng)) goto finish;

    /* print header */
    if (!hndl.dir_addr || (!p_rng && !hndl.dir_sz)) {
        info_dbgprintf("No delayed imports in this module!\n");
        goto finish;
    } else
        info_dbgprintf("Delayed Imports Dir. (DID) at: 0x%p\n", hndl.dir_addr);

    info_dbgprintf("RVA provided in [], 'b:', 'u:', 'h:'"
        " denotes bound addr, original loader addr and hints respectively\n\n");

    DWORD iat_elem_len = (hndl.nt_hdrs.pe_tpy==pe_32bit ?
        sizeof(IMAGE_THUNK_DATA32) : sizeof(IMAGE_THUNK_DATA64));

    img_delay_descr_t did_ent;
    DWORD len_cnstr = (p_rng ? p_rng->rng.len : hndl.dir_sz);

    /* go through DID elems */
    for (ULONG64 did_elem_addr=hndl.dir_addr;;
        did_elem_addr+=sizeof(did_ent),
        len_cnstr-=(len_cnstr!=(DWORD)-1 ? sizeof(did_ent) : 0))
    {
        if (len_cnstr!=(DWORD)-1 && len_cnstr<sizeof(did_ent)) break;

        ULONG cb;
        if (!(read_memory(did_elem_addr, &did_ent, sizeof(did_ent), &cb) &&
            cb==sizeof(did_ent))) break;

        /* zeroed entry marks end of the DID table */
        if (!rmemchr(&did_ent, 0, sizeof(did_ent))) break;

        DWORD attrs = get_32uint_le(&did_ent.attrs);
        BOOL b_rva = (attrs&dlattr_rva)!=0;

        DWORD name_rva = get_32uint_le(&did_ent.rvaDLLName);
        ULONG64 name_addr = RVA2ADDR(name_rva, mod_base);
        if (!b_rva) {
            name_addr=DEBUG_EXTEND64(name_rva);
            name_rva=ADDR2RVA(name_addr, mod_base);
        }

        DWORD hmod_rva = get_32uint_le(&did_ent.rvaHmod);
        ULONG64 hmod_addr = RVA2ADDR(hmod_rva, mod_base);
        if (!b_rva) {
            hmod_addr=DEBUG_EXTEND64(hmod_rva);
            hmod_rva=ADDR2RVA(hmod_addr, mod_base);
        }

        DWORD iat_rva = get_32uint_le(&did_ent.rvaIAT);
        ULONG64 iat_addr = RVA2ADDR(iat_rva, mod_base);
        if (!b_rva) {
            iat_addr=DEBUG_EXTEND64(iat_rva);
            iat_rva=ADDR2RVA(iat_addr, mod_base);
        }

        DWORD ilt_rva = get_32uint_le(&did_ent.rvaILT);
        ULONG64 ilt_addr = RVA2ADDR(ilt_rva, mod_base);
        if (!b_rva) {
            ilt_addr=DEBUG_EXTEND64(ilt_rva);
            ilt_rva=ADDR2RVA(ilt_addr, mod_base);
        }

        DWORD iat_bnd_rva = get_32uint_le(&did_ent.rvaBoundIAT);
        ULONG64 iat_bnd_addr = RVA2ADDR(iat_bnd_rva, mod_base);
        if (!b_rva) {
            iat_bnd_addr=DEBUG_EXTEND64(iat_bnd_rva);
            iat_bnd_rva=ADDR2RVA(iat_bnd_addr, mod_base);
        }

        DWORD iat_unld_rva = get_32uint_le(&did_ent.rvaUnloadIAT);
        ULONG64 iat_unld_addr = RVA2ADDR(iat_unld_rva, mod_base);
        if (!b_rva) {
            iat_unld_addr=DEBUG_EXTEND64(iat_unld_rva);
            iat_unld_rva=ADDR2RVA(iat_unld_addr, mod_base);
        }

        DWORD timestamp = get_32uint_le(&did_ent.dwTimeStamp);

        char mod_name[MAX_PATH+1];
        if (!string_cpy_lt(mod_name, name_addr, sizeof(mod_name)))
            strcpy(mod_name, "???");

        dbgprintf("0x%p[0x%08X] %s DID Entry:\n",
            hndl.dir_addr, ADDR2RVA(hndl.dir_addr, mod_base), mod_name);
        dbgprintf("  Attributes:       0x%08X   ; %s\n",
            attrs, (b_rva ? "rvas in DID" : "real addrs in DID"));
        dbgprintf("  Module name at:   0x%p[0x%08X]\n", name_addr, name_rva);

        ULONG64 mod_hndl;
        char str_mod_hndl[32];
        if (!(read_memory(hmod_addr, &mod_hndl, sizeof(mod_hndl), &cb) &&
            cb==sizeof(mod_hndl)))
        {
            strcpy(str_mod_hndl, "???");
        } else {
            if (hndl.nt_hdrs.pe_tpy==pe_32bit)
                sprintf(str_mod_hndl, "0x%08X", get_32uint_le(&mod_hndl));
            else
                sprintf(str_mod_hndl, "0x%016I64X", get_64uint_le(&mod_hndl));
        }
        dbgprintf("  Module handle at: 0x%p[0x%08X] -> %s\n",
            hmod_addr, hmod_rva, str_mod_hndl);

        dbgprintf("  IAT at:           0x%p[0x%08X]\n", iat_addr, iat_rva);
        dbgprintf("  ILT at:           0x%p[0x%08X]\n", ilt_addr, ilt_rva);
        dbgprintf("  Bound IAT at:     0x%p[0x%08X]\n", iat_bnd_addr, iat_bnd_rva);
        dbgprintf("  Unload IAT at:    0x%p[0x%08X]\n", iat_unld_addr, iat_unld_rva);
        dbgprintf("  Timestamp:        0x%08X   ; %s\n", timestamp,
            (!timestamp ? "not bound" :
            (timestamp==(DWORD)-1 ? "new-type bind" : "old-type bind")));
        dbgprintf(" Imports:\n");

        /* go through ILT elems */
        for (DWORD iat_off=0;; iat_off+=iat_elem_len)
        {
            /* max size to fit 32/64 PE */
            BOOL is_ord;
            ULONG64 ilt_ent;
            ULONG64 proc_addr;

            if (!(read_memory(ilt_addr+iat_off, &ilt_ent, iat_elem_len, &cb) &&
                cb==iat_elem_len)) break;

            /* zeroed entry marks end of the ILT table */
            if (!rmemchr(&ilt_ent, 0, iat_elem_len)) break;

            if (hndl.nt_hdrs.pe_tpy==pe_32bit) {
                ilt_ent = get_32uint_le(&ilt_ent);
                is_ord = IMAGE_SNAP_BY_ORDINAL32(ilt_ent);
            } else {
                ilt_ent = get_64uint_le(&ilt_ent);
                is_ord = IMAGE_SNAP_BY_ORDINAL64(ilt_ent);
            }

            if (read_memory(iat_addr+iat_off, &proc_addr, iat_elem_len, &cb) &&
                cb==iat_elem_len)
            {
                proc_addr = (hndl.nt_hdrs.pe_tpy==pe_32bit ?
                    DEBUG_EXTEND64(get_32uint_le(&proc_addr)) :
                    get_64uint_le(&proc_addr));

                dbgprintf("  0x%p:", proc_addr);
            } else
                dbgprintf("  ???:");

            if (timestamp==(DWORD)-1 && iat_bnd_addr) {
                if (read_memory(iat_bnd_addr+iat_off, &proc_addr, iat_elem_len,
                    &cb) && cb==iat_elem_len)
                {
                    proc_addr = (hndl.nt_hdrs.pe_tpy==pe_32bit ?
                        DEBUG_EXTEND64(get_32uint_le(&proc_addr)) :
                        get_64uint_le(&proc_addr));

                    dbgprintf(" b:0x%p", proc_addr);
                } else
                    dbgprintf(" b:???");
            }

            if (iat_unld_addr) {
                if (read_memory(iat_unld_addr+iat_off, &proc_addr, iat_elem_len,
                    &cb) && cb==iat_elem_len)
                {
                    proc_addr = (hndl.nt_hdrs.pe_tpy==pe_32bit ?
                        DEBUG_EXTEND64(get_32uint_le(&proc_addr)) :
                        get_64uint_le(&proc_addr));

                    dbgprintf(" u:0x%p", proc_addr);
                } else
                    dbgprintf(" u:???");
            }

            if (!is_ord)
            {
                DWORD hnt_rva = ilt_ent;
                ULONG64 hnt_addr = RVA2ADDR(hnt_rva, mod_base);

                dbgprintf(" 0x%p[0x%08X]", hnt_addr, hnt_rva);

                WORD hint;
                char proc_name[MAX_SYM_NAME+1];

                if (!(read_memory(hnt_addr, &hint, sizeof(hint), &cb) &&
                    cb==sizeof(hint))) hint=0;

                hnt_addr += sizeof(hint);

                if (!string_cpy_lt(proc_name, hnt_addr, sizeof(proc_name)))
                    strcpy(proc_name, "???");

                dbgprintf(" h:0x%04X %s", hint, proc_name);
            } else {
                UINT ord = ilt_ent&0xffff;
                dbgprintf(" Ordinal #0x%04X", ord);
            }
            dbgprintf("\n");
        }
    }

finish:
    return;
}

/* module related excerpt from the imports spec. */
typedef struct _impspec_mod_t {
    DWORD iat_rva;
    UINT n_procs;
    DWORD modname_sz;       /* size occupied by the mod name
                               (incl. NULL char, up-rounded to 2) */
} impspec_mod_t;

typedef enum _impsec_elem_id_t
{
   ielem_idt=0,
   ielem_iat,
   ielem_ilt,
   ielem_mod_name
} impsec_elem_id_t;

/* import section's element's spec. */
typedef struct _impsec_elem_t
{
    impsec_elem_id_t tpy;   /* elem's type (ielem_XXX) */
    DWORD rva;              /* elem's rva */
    DWORD sz;               /* elem's size */
    UINT impspec_i;         /* 1-based index of elem in the imports spec config
                               (not relevant for IDT table elem - set to 0) */
} impsec_elem_t;

/* 1 IDT tab + x * (ILT tabs + IAT tabs + mod names) */
#define IMPSEC_ELEMS_NUM(x) (1+3*(x))

/* search IDT handle */
typedef struct _srchidt_hndl_t
{
    static const UINT def_imps_sz = 100;

    /* contains all info related to inspected
       module and parsed import spec. config */
    scan_imps_hndl_t scah;

    /* IAT addresses match table (for unordered search) */
    BOOL *p_unord_finds;
    BOOL unord_finds[def_imps_sz];

    /* import sections elements */
    impsec_elem_t *p_impsec_elems;
    impsec_elem_t impsec_elems[IMPSEC_ELEMS_NUM(def_imps_sz)];
} srchidt_hndl_t;

/* Free search idt handle */
static void free_srchidt_hndl(srchidt_hndl_t *p_hndl)
{
    if (p_hndl->p_unord_finds && p_hndl->p_unord_finds!=&p_hndl->unord_finds[0])
    {
        free(p_hndl->p_unord_finds);
        p_hndl->p_unord_finds = NULL;
    }
    if (p_hndl->p_impsec_elems && p_hndl->p_impsec_elems!=&p_hndl->impsec_elems[0])
    {
        free(p_hndl->p_impsec_elems);
        p_hndl->p_impsec_elems = NULL;
    }

    free_scan_imps_hndl(&p_hndl->scah);
}

/* Initialize search idt handle */
static BOOL init_srchidt_hndl(
    srchidt_hndl_t *p_hndl, ULONG64 mod_base, BOOL b_logs)
{
    BOOL ret=FALSE;

    memset(p_hndl, 0, sizeof(*p_hndl));

    if (!init_scan_imps_hndl(&p_hndl->scah, mod_base, FALSE)) goto finish;

    DWORD iat_sz;
    ULONG64 iat_addr;
    if (!read_imp_spec(&p_hndl->scah, &iat_addr, &iat_sz, TRUE)) goto finish;
    if (!p_hndl->scah.n_mods) {
        if (b_logs) {
            info_dbgprintf("No imports specification found in section [%s]\n",
                PROP_SECT_IMPSPEC);
        }
        goto finish;
    }

    if (p_hndl->scah.n_mods <= p_hndl->def_imps_sz)
    {
        /* set tables to their defaults */
        p_hndl->p_unord_finds = &p_hndl->unord_finds[0];
        p_hndl->p_impsec_elems = &p_hndl->impsec_elems[0];
    } else {
        /* oversized spec. */
        p_hndl->p_unord_finds = (BOOL*)malloc(
            p_hndl->scah.n_mods * sizeof(*(p_hndl->p_unord_finds)));
        p_hndl->p_impsec_elems = (impsec_elem_t*)malloc(
            p_hndl->scah.n_mods * sizeof(*(p_hndl->p_impsec_elems)));

        if (!p_hndl->p_unord_finds || !p_hndl->p_impsec_elems) goto finish;
    }

    ret=TRUE;
finish:
    if (!ret) free_srchidt_hndl(p_hndl);
    return ret;
}

/* Support routine for search_idt(): recognize sections range to search */
static BOOL get_search_sect_range(const srchidt_hndl_t *p_hndl, DWORD sect,
    DWORD *p_start_sect, DWORD *p_end_sect, BOOL *p_b_cont, BOOL b_logs)
{
    BOOL ret=FALSE;
    *p_b_cont = TRUE;

    if (sect==(DWORD)-1)
    {
        /* all sects search */
        *p_start_sect = 0;
        *p_end_sect = p_hndl->scah.n_sects-1;
    } else
    if (1<=sect && sect<=p_hndl->scah.n_sects)
    {
        *p_start_sect = sect-1;
        *p_end_sect = *p_start_sect;
    } else
    {
        /* recognize IAT addresses common sect. */
        DWORD iats_sect=0;
        const imp_mod_desc_t *p_mod;

        for (p_mod=p_hndl->scah.p_imp_mods; p_mod; p_mod=p_mod->next)
        {
            DWORD sect;
            if (get_rva_info(p_hndl->scah.sectab, p_hndl->scah.n_sects,
                ADDR2RVA(p_mod->iat_addr, p_hndl->scah.mod_base), &sect,
                NULL, NULL, NULL))
            {
                if (!iats_sect) iats_sect=sect+1;
                else if (iats_sect!=sect+1) { iats_sect=0; break; }
            } else { iats_sect=0; break; }
        }

        /* section owning the import dir is examined */
        DWORD idt_sect=0;
        IMAGE_DATA_DIRECTORY *p_dd_idt;

        if (get_data_dir(&p_hndl->scah.nt_hdrs, IMAGE_DIRECTORY_ENTRY_IMPORT,
            &p_dd_idt, FALSE))
        {
            DWORD idt_rva = get_32uint_le(&p_dd_idt->VirtualAddress);
            if (idt_rva && get_rva_info(p_hndl->scah.sectab,
                p_hndl->scah.n_sects, idt_rva, &idt_sect, NULL, NULL, NULL))
            {
                idt_sect++;
            }
            else
                idt_sect=0;
        }

        if (iats_sect && idt_sect) {
            *p_start_sect = iats_sect-1;
            *p_end_sect = idt_sect-1;
            *p_b_cont = FALSE;
        } else
        if (iats_sect || idt_sect) {
            *p_start_sect = (iats_sect ? iats_sect : idt_sect)-1;
            *p_end_sect = *p_start_sect;
        } else {
            if (b_logs)
                err_dbgprintf("Can not establish sections for IDT searching\n");
            goto finish;
        }
    }

    ret=TRUE;
finish:
    return ret;
}

/* Import section elements comparator */
static int cmp_impsec_elems(const void *a, const void *b)
{
    return ((impsec_elem_t*)a)->rva - ((impsec_elem_t*)b)->rva;
}

/* Support routine for search_idt(): add import section element to the list.
   Returns TRUE for the last element
 */
static BOOL add_impsec_elem(srchidt_hndl_t *p_hndl,
    const IMAGE_IMPORT_DESCRIPTOR *p_idt_ent, UINT srch_i,
    UINT impspec_i, ULONG64 srch_addr)
{
    BOOL b_last=FALSE;

    DWORD iat_elem_len =
        (p_hndl->scah.nt_hdrs.pe_tpy==pe_32bit ?
        sizeof(IMAGE_THUNK_DATA32) : sizeof(IMAGE_THUNK_DATA64));

    imp_mod_desc_t *p_mod = get_imp_mod(p_hndl->scah.p_imp_mods, impspec_i-1);

    /* IAT elem */
    p_hndl->p_impsec_elems[3*srch_i].tpy = ielem_iat;
    p_hndl->p_impsec_elems[3*srch_i].rva = get_32uint_le(&p_idt_ent->FirstThunk);
    p_hndl->p_impsec_elems[3*srch_i].sz = (p_mod->n_procs+1)*iat_elem_len;
    p_hndl->p_impsec_elems[3*srch_i].impspec_i = impspec_i;

    /* ILT elem */
    p_hndl->p_impsec_elems[3*srch_i+1].tpy = ielem_ilt;
    p_hndl->p_impsec_elems[3*srch_i+1].rva =
        get_32uint_le(&p_idt_ent->OriginalFirstThunk);
    p_hndl->p_impsec_elems[3*srch_i+1].sz = p_hndl->p_impsec_elems[3*srch_i].sz;
    p_hndl->p_impsec_elems[3*srch_i+1].impspec_i = impspec_i;

    /* mod name elem */
    p_hndl->p_impsec_elems[3*srch_i+2].tpy = ielem_mod_name;
    p_hndl->p_impsec_elems[3*srch_i+2].rva = get_32uint_le(&p_idt_ent->Name);
    p_hndl->p_impsec_elems[3*srch_i+2].sz = RNDUP_W(strlen(p_mod->name)+1);
    p_hndl->p_impsec_elems[3*srch_i+2].impspec_i = impspec_i;

    if (srch_i+1 >= p_hndl->scah.n_mods)
    {
        /* IDT elem */
        p_hndl->p_impsec_elems[3*srch_i+3].tpy = ielem_idt;
        p_hndl->p_impsec_elems[3*srch_i+3].rva =
            ADDR2RVA(srch_addr, p_hndl->scah.mod_base);
        p_hndl->p_impsec_elems[3*srch_i+3].sz =
            (p_hndl->scah.n_mods+1)*sizeof(IMAGE_IMPORT_DESCRIPTOR);
        p_hndl->p_impsec_elems[3*srch_i+3].impspec_i = 0;

        /* last IDT elem should be zero'ed */
        ULONG cb;
        IMAGE_IMPORT_DESCRIPTOR null_ent;
        ULONG64 null_addr =
            srch_addr + p_hndl->scah.n_mods*sizeof(IMAGE_IMPORT_DESCRIPTOR);

        if (!(read_memory(null_addr, &null_ent, sizeof(null_ent), &cb) &&
            cb==sizeof(null_ent)) || rmemchr(&null_ent, 0, sizeof(null_ent)))
        {
            warn_dbgprintf(
                "IDT table is not properly finished with last zero'ed element\n");
        }

        /* finally sort the import sections elements */
        qsort(p_hndl->p_impsec_elems, IMPSEC_ELEMS_NUM(p_hndl->scah.n_mods),
            sizeof(*(p_hndl->p_impsec_elems)), cmp_impsec_elems);

        b_last=TRUE;
    }

    return b_last;
}

/* Support routine for search_idt(): analyse & print import section elems layout */
static void analyse_impsec_lout(const srchidt_hndl_t *p_hndl, BOOL b_logs)
{
    /* overall module names size (rounded & unrounded) */
    DWORD modns_sz=0, modns_nrnd_sz=0;
    /* overall module names + hint/name tabs size (rounded & unrounded) */
    DWORD hns_modns_sz=0, hns_modns_nrnd_sz=0;

    /* last continuous mod names block */
    struct {
        BOOL b_rd_bl;   /* block is currently read */
        UINT n_bls;     /* number of read blocks */
        DWORD rva_beg;  /* last block beginning rva */
        DWORD rva_end;  /* last block ending rva */
    } lcnb = {};

    /* rounded names indicator */
    BOOL b_rnd_names=TRUE;

    /* no ILTs indicator */
    BOOL b_no_ilts=TRUE;

    DWORD cont_sect;

    if (b_logs) info_dbgprintf("Import section elements layout:\n");

    for (UINT i=0; i < IMPSEC_ELEMS_NUM(p_hndl->scah.n_mods); i++)
    {
        impsec_elem_id_t tpy = p_hndl->p_impsec_elems[i].tpy;
        DWORD rva = p_hndl->p_impsec_elems[i].rva;
        DWORD sz = p_hndl->p_impsec_elems[i].sz;
        UINT impspec_i = p_hndl->p_impsec_elems[i].impspec_i;

        imp_mod_desc_t *p_mod = get_imp_mod(p_hndl->scah.p_imp_mods, impspec_i-1);

        /* get owning sect */
        DWORD sect_i;
        if (!get_rva_info(p_hndl->scah.sectab, p_hndl->scah.n_sects,
            rva, &sect_i, NULL, NULL, NULL)) sect_i=(DWORD)-1;

        /* calc gaps (previous & next) */
        DWORD rvasz_prev=rva;
        INT32 gap_prev=0, gap_next=0;

        if (i) {
            rvasz_prev =
                p_hndl->p_impsec_elems[i-1].rva + p_hndl->p_impsec_elems[i-1].sz;
            gap_prev = rva - rvasz_prev;
        }
        if (i+1 < IMPSEC_ELEMS_NUM(p_hndl->scah.n_mods)) {
            gap_next = p_hndl->p_impsec_elems[i+1].rva-(rva+sz);
        }

        /* detect cleared ILT rvas, as build by some compilers */
        if (tpy==ielem_ilt && rva) b_no_ilts=FALSE;

        /* read continuous mod names block */
        if (tpy==ielem_mod_name)
        {
            /* update mod names size */
            size_t modn_nrnd_sz = strlen(p_mod->name)+1;
            size_t modn_sz = RNDUP_W(modn_nrnd_sz);
            modns_sz += modn_sz;
            hns_modns_sz += p_mod->hnt_sz+modn_sz;
            modns_nrnd_sz += modn_nrnd_sz;
            hns_modns_nrnd_sz += p_mod->hnt_nrnd_sz+modn_nrnd_sz;

            /* detect unrounded mod names */
            if (gap_next==-1 && modn_nrnd_sz<modn_sz) b_rnd_names=FALSE;

            if (!lcnb.b_rd_bl) {
                lcnb.n_bls++;
                lcnb.b_rd_bl = TRUE;
                lcnb.rva_beg = rva-gap_prev;
            } else
                lcnb.rva_end = rva+sz;
        } else
        if (lcnb.b_rd_bl) lcnb.b_rd_bl=FALSE;

        /* print current elem details */
        if (b_logs)
        {
            if (!i || cont_sect!=sect_i) {
                if (sect_i!=(DWORD)-1) dbgprintf("Section %d\n", sect_i+1);
                else dbgprintf("Outside sections\n");

                cont_sect=sect_i;
            }

            if (gap_prev>0) {
                dbgprintf(" 0x%p[0x%08X] 0x%04X: <gap>\n",
                    RVA2ADDR(rvasz_prev, p_hndl->scah.mod_base), rvasz_prev,
                    gap_prev);
            }

            dbgprintf(" 0x%p[0x%08X] 0x%04X",
                RVA2ADDR(rva, p_hndl->scah.mod_base), rva, sz);

            if (gap_prev<0) dbgprintf(" OVERLAPPED[0x%04X]", -gap_prev);
            dbgprintf(": ");

            const char *pc_mod_name = NULL;
            if (p_mod) pc_mod_name = (*(p_mod->name) ? p_mod->name : "<unspec>");

            switch (tpy) {
                case ielem_idt:
                    dbgprintf("IDT\n");
                    break;
                case ielem_iat:
                    dbgprintf("IAT of %s\n", pc_mod_name);
                    break;
                case ielem_ilt:
                    dbgprintf("ILT of %s\n", pc_mod_name);
                    break;
                case ielem_mod_name:
                    dbgprintf("Name of %-16s h/n size:0x%04X, not-rnd:0x%04X\n",
                        pc_mod_name, p_mod->hnt_sz, p_mod->hnt_nrnd_sz);
                    break;
            }
        }
    }

    /* mod names block analysis
     */
    DWORD modns_rva=(DWORD)-1, hns_rva=(DWORD)-1, hns_modns_rva=(DWORD)-1;

    if (lcnb.n_bls==1)
    {
        DWORD last_rva, last_raw_rem, err_last_not_suff=0;

        if (lcnb.b_rd_bl)
        {
            /* mod names at the end of import sect. */
            last_rva = hns_modns_rva = lcnb.rva_beg;

            if (!get_rva_info(p_hndl->scah.sectab, p_hndl->scah.n_sects,
                last_rva, NULL, &last_raw_rem, NULL, NULL)) last_raw_rem=0;

            if (last_raw_rem < hns_modns_nrnd_sz) {
                err_last_not_suff = hns_modns_nrnd_sz;
            } else
            if (last_raw_rem < hns_modns_sz) b_rnd_names=FALSE;
        } else
        {
            /* mod names inserted into import sect. */
            DWORD bl_sz = lcnb.rva_end-lcnb.rva_beg;
            UINT li = IMPSEC_ELEMS_NUM(p_hndl->scah.n_mods)-1;
            last_rva =
                p_hndl->p_impsec_elems[li].rva + p_hndl->p_impsec_elems[li].sz;

            if (!get_rva_info(p_hndl->scah.sectab, p_hndl->scah.n_sects,
                last_rva, NULL, &last_raw_rem, NULL, NULL)) last_raw_rem=0;

            if (bl_sz>=modns_nrnd_sz)
            {
                if (bl_sz>=modns_sz)
                {
                    if (bl_sz>=hns_modns_nrnd_sz)
                    {
                        if (bl_sz>=hns_modns_sz) {
                            hns_modns_rva = lcnb.rva_beg;
                        } else {
                            b_rnd_names = FALSE;
                            hns_modns_rva = lcnb.rva_beg;
                        }
                    } else {
                        modns_rva = lcnb.rva_beg;
                        hns_rva = last_rva;

                        if (last_raw_rem < hns_modns_nrnd_sz-modns_nrnd_sz) {
                            err_last_not_suff = hns_modns_nrnd_sz-modns_nrnd_sz;
                        } else
                        if (last_raw_rem < hns_modns_sz-modns_sz)
                            b_rnd_names=FALSE;
                    }
                } else {
                    b_rnd_names = FALSE;
                    modns_rva = lcnb.rva_beg;
                    hns_rva = last_rva;

                    if (last_raw_rem < hns_modns_nrnd_sz-modns_nrnd_sz)
                        err_last_not_suff = hns_modns_nrnd_sz-modns_nrnd_sz;
                }
            } else
            if (b_logs) warn_dbgprintf("Module names block too small\n");
        }

        if (err_last_not_suff && b_logs) {
            warn_dbgprintf("Insufficient raw space (0x%04X) to fit 0x%04X bytes; "
                "0x%p[0x%08X]\n", last_raw_rem, err_last_not_suff,
                RVA2ADDR(last_rva, p_hndl->scah.mod_base), last_rva);
        }
    } else
    if (lcnb.n_bls>0 && b_logs) {
        warn_dbgprintf(
            "Import section contains more than one module names block\n");
    }

    /* print results
     */
    if (!b_rnd_names || b_no_ilts || modns_rva!=(DWORD)-1 ||
        hns_modns_rva!=(DWORD)-1)
    {
        if (!b_logs) dbgprintf("[%s]\n", PROP_SECT_IMPFIX);

        if (!b_rnd_names)
        {
            if (b_logs) {
                info_dbgprintf(
                    "Module and import names are not 2-bytes zero padded\n");
            } else {
                dbgprintf("%s = 1\n", PROP_IMPFIX_NO_PADD_NAMES);
            }
        }

        if (b_no_ilts)
        {
            if (b_logs) {
                info_dbgprintf("Import directory with no ILT tables\n");
            } else {
                dbgprintf("%s = 1\n", PROP_IMPFIX_NO_ILTS);
            }
        }

        if (modns_rva!=(DWORD)-1)
        {
            if (b_logs) {
                info_dbgprintf("Module names at 0x%p[0x%08X] 0x%04X, separated "
                    "from Hint/Name table at 0x%p[0x%08X] 0x%04X\n",
                    RVA2ADDR(modns_rva, p_hndl->scah.mod_base), modns_rva,
                    (b_rnd_names ? modns_sz : modns_nrnd_sz),
                    RVA2ADDR(hns_rva, p_hndl->scah.mod_base), hns_rva,
                    (b_rnd_names ? hns_modns_sz-modns_sz :
                        hns_modns_nrnd_sz-modns_nrnd_sz));
            } else {
                dbgprintf("%s = 0x%08X\n", PROP_IMPFIX_NAME_TAB_RVA, modns_rva);
                dbgprintf("%s = 0x%08X\n", PROP_IMPFIX_HN_TAB_RVA, hns_rva);
            }
        } else
        if (hns_modns_rva!=(DWORD)-1)
        {
            if (b_logs) {
                info_dbgprintf("Module names and Hint/Name table at 0x%p[0x%08X] "
                    "0x%04X\n", RVA2ADDR(hns_modns_rva, p_hndl->scah.mod_base),
                    hns_modns_rva,
                    (b_rnd_names ? hns_modns_sz : hns_modns_nrnd_sz));
            } else {
                dbgprintf("%s = 0x%08X\n", PROP_IMPFIX_HN_TAB_RVA, hns_modns_rva);
            }
        }
    }

    return;
}

/* exported; see header for details */
void search_idt(ULONG64 mod_base, const rng_spec_t *p_rng, DWORD flags)
{
    srchidt_hndl_t hndl;

    BOOL b_logs = !(flags&SRCHIDT_SILENT);

    if (!init_srchidt_hndl(&hndl, mod_base, b_logs)) goto finish;

    DWORD start_sect=0, end_sect=0;
    BOOL b_sect_cont=TRUE, b_sect_srch;
    if (!p_rng || p_rng->is_sect)
    {
        /* establish sections range to search */
        if (!get_search_sect_range(&hndl, (p_rng ? p_rng->sect : 0),
            &start_sect, &end_sect, &b_sect_cont, b_logs)) goto finish;

        b_sect_srch=TRUE;
    } else {
        if (!p_rng->rng.len || p_rng->rng.len==(DWORD)-1) goto finish;
        b_sect_srch=FALSE;
    }

    ULONG64 srch_addr;
    BOOL found=FALSE, unord=FALSE;

    /* go through inspected sections */
    for (DWORD sect_i=start_sect;
        !found && (b_sect_cont ? sect_i<=end_sect :
            sect_i==start_sect || sect_i==end_sect);
        (b_sect_cont ? sect_i++ :
            sect_i=(sect_i==start_sect ? end_sect : (DWORD)-1)))
    {
        DWORD srch_sz;
        ULONG64 start_addr;
        if (b_sect_srch)
        {
            ULONG64 sect_addr = RVA2ADDR(get_32uint_le(
                &hndl.scah.sectab[sect_i].VirtualAddress), hndl.scah.mod_base);
            DWORD sect_vsz = get_32uint_le(
                &hndl.scah.sectab[sect_i].Misc.VirtualSize);

            start_addr=sect_addr;
            srch_sz=sect_vsz;

            if (b_logs) {
                info_dbgprintf("Inspecting section %d starting "
                    "at: 0x%p, size: 0x%08X\n", sect_i+1, start_addr, srch_sz);
            }
        } else
        {
            start_addr = (p_rng->rng.is_rva ?
                RVA2ADDR(p_rng->rng.rva, mod_base) : p_rng->rng.addr);
            srch_sz = p_rng->rng.len;

            if (b_logs) {
                info_dbgprintf(
                    "Inspecting memory range starting at: 0x%p", start_addr);
                if (srch_sz!=(DWORD)-1) dbgprintf(", size: 0x%08X\n", srch_sz);
                else dbgprintf("\n");
            }
        }

        srch_addr=start_addr;
        DWORD off=0, srch_i=0;

        /* searching loop (starting from srch_addr) */
        IMAGE_IMPORT_DESCRIPTOR idt_ent;
        while (srch_addr+sizeof(idt_ent) <= start_addr+srch_sz)
        {
            ULONG cb;
            if (!(read_memory(srch_addr+off, &idt_ent, sizeof(idt_ent), &cb) &&
                cb==sizeof(idt_ent))) break;

            UINT impspec_i=0;   /* 1-based, 0-IAT addr not match */
            DWORD iat_rva = get_32uint_le(&idt_ent.FirstThunk);

            if (flags&SRCHIDT_NO_ORD)
            {
                /* searched IAT addresses are unordered */
                imp_mod_desc_t *p_mod = hndl.scah.p_imp_mods;
                for (UINT i=0; p_mod; i++, p_mod=p_mod->next)
                {
                    if (ADDR2RVA(p_mod->iat_addr, hndl.scah.mod_base)==iat_rva)
                    {
                        if (!hndl.p_unord_finds[i]) {
                            impspec_i=i+1;
                            hndl.p_unord_finds[i]=TRUE;
                            if (!unord && i!=srch_i) unord=TRUE;
                        }
                        break;
                    }
                }
            } else {
                /* searched IAT addresses must occur as in the import spec. cfg */
                imp_mod_desc_t *p_mod = get_imp_mod(hndl.scah.p_imp_mods, srch_i);

                if (ADDR2RVA(p_mod->iat_addr, hndl.scah.mod_base)==iat_rva)
                        impspec_i=srch_i+1;
            }

            if (impspec_i)
            {
                if (!add_impsec_elem(
                    &hndl, &idt_ent, srch_i, impspec_i, srch_addr))
                {
                    /* check next IAT address in the next iter */
                    off+=sizeof(idt_ent);
                    srch_i++;
                } else {
                    /* all IAT addresses matches */
                    found=TRUE;
                    break;
                }
            } else {
                /* IAT doesn't match; continue search from the subsequent addr */
                srch_addr++;
                off=0;
                srch_i=0;
                unord=FALSE;
                if (flags&SRCHIDT_NO_ORD) {
                    memset(hndl.p_unord_finds, 0,
                        hndl.scah.n_mods*sizeof(*(hndl.p_unord_finds)));
                }
            }
        }
    }

    if (found)
    {
        if (b_logs)
        {
            info_dbgprintf("IDT table found at: 0x%p, rva: 0x%08X\n", srch_addr,
                ADDR2RVA(srch_addr, hndl.scah.mod_base));

            if ((flags&SRCHIDT_NO_ORD) && unord)
                info_dbgprintf("The IDT table contains IAT addresses in order "
                    "different as specified in the imports spec. config\n");
        } else {
            dbgprintf("[%s]\n%s = 0x%08X\n", PROP_SECT_DIRS, PROP_DIRS_IDT_RVA,
                ADDR2RVA(srch_addr, hndl.scah.mod_base));
        }

        analyse_impsec_lout(&hndl, b_logs);
    } else {
        if (b_logs) info_dbgprintf("IDT table not found!\n");
    }

finish:
    free_srchidt_hndl(&hndl);
    return;
}
