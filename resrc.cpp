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
#include "pebase.h"
#include "resrc.h"

typedef enum _rsrc_level_t
{
    lev_root=0,     /* 0 level - root */
    lev_type,       /* type level */
    lev_name,       /* name level */
    lev_lang        /* instance (per language) */
} rsrc_level_t;

typedef struct _rsrc_entry_t
{
    /* 0 for the root level
      (rsrc_level_t enums may be used for the standard levels) */
    UINT level;

    /* index val in the level
       (not related for the root level) */
    UINT level_i;

    /* next/prev levels entries */
    struct _rsrc_entry_t *p_next;
    struct _rsrc_entry_t *p_prev;

    /* entry id/offset
      (not related for the root level) */
    IMAGE_RESOURCE_DIRECTORY_ENTRY dir_ent;
} rsrc_entry_t;

typedef enum _rsrc_elem_tpy_t
{
    rse_dir=0,      /* directory */
    rse_dta_ent,    /* data entry */
    rse_name,       /* element name */
    rse_dta_inst    /* data instance */
} rsrc_elem_tpy_t;

typedef struct _rsrc_elem_sizes_t
{
    DWORD no_padd;   /* no padded size */
    DWORD w_padd;    /* word padded size */
    DWORD dw_padd;   /* dword padded size */

    DWORD off;       /* reserved for recovery algo:
                        incremental write offset */
} rsrc_elem_sizes_t;

/* resources capacity stats */
typedef struct _rsrc_cap_stats_t
{
    /* invalid state (can't establish stats) */
    BOOL b_invalid;

    /* some data outside of sects scope detected */
    BOOL b_out_sscope;

    /* occupied sects (0-based indexes) */
    UINT n_sects;
    UINT sects[MAX_SECTIONS];

    /* total sizes */
    rsrc_elem_sizes_t total_sz;

    /* dirs sizes (per level) */
    UINT dir_szs_sz;                /* dirs sizes table size */
    rsrc_elem_sizes_t *p_dir_szs;
    rsrc_elem_sizes_t dir_szs[32];  /* default dirs sizes table */

    /* data entries sizes */
    rsrc_elem_sizes_t dta_ent_sz;

    /* names sizes */
    rsrc_elem_sizes_t name_sz;

    /* data instances sizes */
    rsrc_elem_sizes_t dta_inst_sz;
} rsrc_cap_stats_t;

/* resources fix handle */
typedef struct _rsrc_fix_hndl_t
{
    ULONG64 mod_base;
    image_nt_headers_t nt_hdrs;

    /* sections table */
    DWORD n_sects;
    IMAGE_SECTION_HEADER sectab[MAX_SECTIONS];

    DWORD dir_rsrc_sz;          /* rsrc dir size (as read PE header or conf) */
    DWORD rcv_rsrc_sz;          /* recovered rsrc size */

    ULONG64 src_rsrc_addr;      /* source addr of rsrc to fix */
    ULONG64 dst_rsrc_addr;      /* destination addr of fixed rsrc */

    rsrc_cap_stats_t cstats;    /* capacity stats */

    padd_val_t padd;

    FILE *fh;                   /* out file handle */
    char fname[MAX_PATH+1];     /* out file name */
} rsrc_fix_hndl_t;

static struct
{
    UINT code;
    const char *pc_name;
} lcids[] =
{
    {0, "unicode"},  {1025, "ar-sa"}, {1026, "bg"},    {1027, "ca"},
    {1028, "zh-tw"}, {1029, "cs"},    {1030, "da"},    {1031, "de-de"},
    {1032, "el"},    {1033, "en-us"}, {1034, "es-es"}, {1035, "fi"},
    {1036, "fr-fr"}, {1037, "he"},    {1038, "hu"},    {1039, "is"},
    {1040, "it-it"}, {1041, "ja"},    {1042, "ko"},    {1043, "nl-nl"},
    {1044, "no-no"}, {1045, "pl"},    {1046, "pt-br"}, {1047, "rm"},
    {1048, "ro"},    {1049, "ru"},    {1050, "hr"},    {1051, "sk"},
    {1052, "sq"},    {1053, "sv-se"}, {1054, "th"},    {1055, "tr"},
    {1056, "ur"},    {1057, "id"},    {1058, "uk"},    {1059, "be"},
    {1060, "sl"},    {1061, "et"},    {1062, "lv"},    {1063, "lt"},
    {1064, "tg"},    {1065, "fa"},    {1066, "vi"},    {1067, "hy"},
    {1068, "az-az"}, {1069, "eu"},    {1070, "sb"},    {1071, "mk"},
    {1073, "ts"},    {1074, "tn"},    {1076, "xh"},    {1077, "zu"},
    {1078, "af"},    {1079, "ka"},    {1080, "fo"},    {1081, "hi"},
    {1082, "mt"},    {1084, "gd"},    {1085, "yi"},    {1086, "ms-my"},
    {1087, "kk"},    {1089, "sw"},    {1090, "tk"},    {1091, "uz-uz"},
    {1092, "tt"},    {1093, "bn"},    {1094, "pa"},    {1095, "gu"},
    {1096, "or"},    {1097, "ta"},    {1098, "te"},    {1099, "kn"},
    {1100, "ml"},    {1101, "as"},    {1102, "mr"},    {1103, "sa"},
    {1104, "mn"},    {1105, "bo"},    {1106, "cy"},    {1107, "km"},
    {1108, "lo"},    {1109, "my"},    {1110, "gl"},    {1113, "sd"},
    {1115, "si"},    {1118, "am"},    {1120, "ks"},    {1121, "ne"},
    {1125, "dv"},    {1140, "gn"},    {1142, "la"},    {1143, "so"},
    {1153, "mi"},    {2049, "ar-iq"}, {2052, "zh-cn"}, {2055, "de-ch"},
    {2057, "en-gb"}, {2058, "es-mx"}, {2060, "fr-be"}, {2064, "it-ch"},
    {2067, "nl-be"}, {2068, "no-no"}, {2070, "pt-pt"}, {2072, "ro-mo"},
    {2073, "ru-mo"}, {2074, "sr-sp"}, {2077, "sv-fi"}, {2092, "az-az"},
    {2108, "gd-ie"}, {2110, "ms-bn"}, {2115, "uz-uz"}, {2117, "bn"},
    {2128, "mn"},    {3073, "ar-eg"}, {3076, "zh-hk"}, {3079, "de-at"},
    {3081, "en-au"}, {3084, "fr-ca"}, {3098, "sr-sp"}, {4097, "ar-ly"},
    {4100, "zh-sg"}, {4103, "de-lu"}, {4105, "en-ca"}, {4106, "es-gt"},
    {4108, "fr-ch"}, {5121, "ar-dz"}, {5124, "zh-mo"}, {5127, "de-li"},
    {5129, "en-nz"}, {5130, "es-cr"}, {5132, "fr-lu"}, {5146, "bs"},
    {6145, "ar-ma"}, {6153, "en-ie"}, {6154, "es-pa"}, {7169, "ar-tn"},
    {7177, "en-za"}, {7178, "es-do"}, {8193, "ar-om"}, {8201, "en-jm"},
    {8202, "es-ve"}, {9217, "ar-ye"}, {9225, "en-cb"}, {9226, "es-co"},
    {10241, "ar-sy"},{10249, "en-bz"},{10250, "es-pe"},{11265, "ar-jo"},
    {11273, "en-tt"},{11274, "es-ar"},{12289, "ar-lb"},{12298, "es-ec"},
    {13313, "ar-kw"},{13321, "en-ph"},{13322, "es-cl"},{14337, "ar-ae"},
    {14346, "es-uy"},{15361, "ar-bh"},{15370, "es-py"},{16385, "ar-qa"},
    {16393, "en-in"},{16394, "es-bo"},{17418, "es-sv"},{18442, "es-hn"},
    {19466, "es-ni"},{20490, "es-pr"}
};


/* Get lcis name; NULL if not recognized */
static const char *get_lcid_name(UINT lcid)
{
    const char *ret=NULL;
    for (UINT i=0; i<sizeof(lcids)/sizeof(lcids[0]); i++)
        if (lcids[i].code==lcid) { ret=lcids[i].pc_name; break; }

    return ret;
}

/* Get rsrc type name; NULL if not recognized */
static const char *get_rsrctpy_name(WORD tpy)
{
    const char *ret=NULL;
    switch (tpy) {
        case (WORD)RT_CURSOR: ret="RT_CURSOR"; break;
        case (WORD)RT_BITMAP: ret="RT_BITMAP"; break;
        case (WORD)RT_ICON: ret="RT_ICON"; break;
        case (WORD)RT_MENU: ret="RT_MENU"; break;
        case (WORD)RT_DIALOG: ret="RT_DIALOG"; break;
        case (WORD)RT_STRING: ret="RT_STRING"; break;
        case (WORD)RT_FONTDIR: ret="RT_FONTDIR"; break;
        case (WORD)RT_FONT: ret="RT_FONT"; break;
        case (WORD)RT_ACCELERATOR: ret="RT_ACCELERATOR"; break;
        case (WORD)RT_RCDATA: ret="RT_RCDATA"; break;
        case (WORD)RT_MESSAGETABLE: ret="RT_MESSAGETABLE"; break;
        case (WORD)RT_GROUP_CURSOR: ret="RT_GROUP_CURSOR"; break;
        case (WORD)RT_GROUP_ICON: ret="RT_GROUP_ICON"; break;
        case (WORD)RT_VERSION: ret="RT_VERSION"; break;
        case (WORD)RT_DLGINCLUDE: ret="RT_DLGINCLUDE"; break;
        case (WORD)RT_PLUGPLAY: ret="RT_PLUGPLAY"; break;
        case (WORD)RT_VXD: ret="RT_VXD"; break;
        case (WORD)RT_ANICURSOR: ret="RT_ANICURSOR"; break;
        case (WORD)RT_ANIICON: ret="RT_ANIICON"; break;
        case (WORD)RT_HTML: ret="RT_HTML"; break;
        case (WORD)RT_MANIFEST: ret="RT_MANIFEST"; break;
    }
    return ret;
}

/* Initialize capacity stats struct */
static void init_cstats(rsrc_cap_stats_t *p_cstats)
{
    memset(p_cstats, 0, sizeof(*p_cstats));

    p_cstats->p_dir_szs = p_cstats->dir_szs;
    p_cstats->dir_szs_sz =
        sizeof(p_cstats->dir_szs)/sizeof(p_cstats->dir_szs[0]);
}

/* Free capacity stats struct */
static void free_cstats(rsrc_cap_stats_t *p_cstats)
{
    if (p_cstats->p_dir_szs!=p_cstats->dir_szs && p_cstats->p_dir_szs)
        free(p_cstats->p_dir_szs);

    memset(p_cstats, 0, sizeof(*p_cstats));
    p_cstats->b_invalid=TRUE;
}

/* Update capacity stats of a resource element with type 'rse_tpy' on 'level'
   with 'rva' and size 'sz'.
 */
static void update_cstats(
    const prnt_dir_hndl_t *p_hndl, rsrc_cap_stats_t *p_cstats,
    rsrc_elem_tpy_t rse_tpy, UINT level, DWORD rva, DWORD sz)
{
    if (!p_cstats || p_cstats->b_invalid) goto finish;

    /* update containing sects */
    DWORD sect_i, n_va_rem;
    if (get_rva_info(
        p_hndl->sectab, p_hndl->n_sects, rva, &sect_i, NULL, &n_va_rem, NULL))
    {
        if (sz > n_va_rem) p_cstats->b_out_sscope=TRUE;

        UINT i;
        for (i=0; i<p_cstats->n_sects; i++) if (p_cstats->sects[i]==sect_i)
            break;

        /* will never happen to go outside max. of sects table */
        if (i>=p_cstats->n_sects && p_cstats->n_sects<MAX_SECTIONS)
            p_cstats->sects[p_cstats->n_sects++]=sect_i;
    } else {
        p_cstats->b_out_sscope=TRUE;
    }

    /* update sizes */
    p_cstats->total_sz.no_padd += sz;
    p_cstats->total_sz.w_padd += RNDUP_W(sz);
    p_cstats->total_sz.dw_padd += RNDUP_DW(sz);

    switch (rse_tpy)
    {
    case rse_dir:
      {
        if (level>=p_cstats->dir_szs_sz)
        {
            /* reallocation shall never happen for standard resources */
            UINT new_dir_szs_sz = RNDUP(level+1,
                sizeof(p_cstats->dir_szs)/sizeof(p_cstats->dir_szs[0]));

            rsrc_elem_sizes_t *p_new_dir_szs =
                (rsrc_elem_sizes_t*)malloc(sizeof(*p_new_dir_szs)*new_dir_szs_sz);
            if (p_new_dir_szs)
            {
                memset(p_new_dir_szs, 0, sizeof(*p_new_dir_szs)*new_dir_szs_sz);
                memcpy(p_new_dir_szs, p_cstats->p_dir_szs,
                    sizeof(*(p_cstats->p_dir_szs))*p_cstats->dir_szs_sz);

                if (p_cstats->p_dir_szs!=p_cstats->dir_szs)
                    free(p_cstats->p_dir_szs);

                p_cstats->p_dir_szs = p_new_dir_szs;
                p_cstats->dir_szs_sz = new_dir_szs_sz;
            } else {
                free_cstats(p_cstats);
                break;
            }
        }
        p_cstats->p_dir_szs[level].no_padd += sz;
        p_cstats->p_dir_szs[level].w_padd += RNDUP_W(sz);
        p_cstats->p_dir_szs[level].dw_padd += RNDUP_DW(sz);
        break;
      }
    case rse_dta_ent:
        p_cstats->dta_ent_sz.no_padd += sz;
        p_cstats->dta_ent_sz.w_padd += RNDUP_W(sz);
        p_cstats->dta_ent_sz.dw_padd += RNDUP_DW(sz);
        break;
    case rse_name:
        p_cstats->name_sz.no_padd += sz;
        p_cstats->name_sz.w_padd += RNDUP_W(sz);
        p_cstats->name_sz.dw_padd += RNDUP_DW(sz);
        break;
    case rse_dta_inst:
        p_cstats->dta_inst_sz.no_padd += sz;
        p_cstats->dta_inst_sz.w_padd += RNDUP_W(sz);
        p_cstats->dta_inst_sz.dw_padd += RNDUP_DW(sz);
        break;
    }

finish:
    return;
}

/* Invalidate capacity stats */
static inline void invalidate_cstats(rsrc_cap_stats_t *p_cstats) {
    if (p_cstats) p_cstats->b_invalid=TRUE;
}

/* Initialize root entry */
static void init_root_ent(rsrc_entry_t *p_ent)
{
    memset(p_ent, 0, sizeof(*p_ent));
}

/* Print resource dir details and if 'p_cstats' is not NULL, read and store
   capacity statistics.
 */
static void print_rsrc_ent(const prnt_dir_hndl_t *p_hndl,
    rsrc_entry_t *p_ent, rsrc_cap_stats_t *p_cstats)
{
    const UINT max_idents = 16;
    const UINT ident_sz = 4;

    /* prepare level ident */
    char spc[ident_sz*max_idents+1];
    memset(spc, ' ', sizeof(spc)-1);

    UINT spc_sz = ident_sz*p_ent->level;
    if (p_ent->level <= max_idents) spc[spc_sz]=0;
    else spc[sizeof(spc)-1] = 0;

    /* entry header
     */

    /* indexed header */
    rsrc_entry_t *p_sup_ent;
    for (p_sup_ent=p_ent; p_sup_ent->p_prev; p_sup_ent=p_sup_ent->p_prev);

    UINT hidx_sz=0;     /* indexed header size */
    p_sup_ent=p_sup_ent->p_next;
    for (UINT i=1; p_sup_ent; i++, p_sup_ent=p_sup_ent->p_next) {
        if (i<=max_idents) {
            dbgprintf((p_sup_ent->p_next ?
                (hidx_sz+=1, ".%d") : (hidx_sz+=2, ".%d ")), p_sup_ent->level_i);
            for (UINT d=p_sup_ent->level_i; d; d/=10) hidx_sz++;
        } else {
            dbgprintf("... ");
            hidx_sz+=4;
            break;
        }
    }
    if (hidx_sz<spc_sz) dbgprintf(spc+hidx_sz);

    BOOL is_dir = TRUE;
    ULONG64 ent_addr = p_hndl->dir_addr;

    /* entry address */
    dbgprintf("0x%p", p_hndl->dir_addr);
    if (p_ent->level > lev_root)
    {
        DWORD off_dta = get_32uint_le(&p_ent->dir_ent.OffsetToData);
        is_dir = (off_dta&IMAGE_RESOURCE_DATA_IS_DIRECTORY)!=0;
        off_dta &= ~IMAGE_RESOURCE_DATA_IS_DIRECTORY;
        ent_addr += off_dta;

        dbgprintf("+0x%04X", off_dta);
    }
    dbgprintf("[0x%08X] ", ADDR2RVA(ent_addr, p_hndl->mod_base));

    /* entry type */
    if (is_dir) {
        switch (p_ent->level) {
        case lev_root: dbgprintf("RootDir"); break;
        case lev_type: dbgprintf("TypeDir"); break;
        case lev_name: dbgprintf("NameDir"); break;
        default: dbgprintf("Dir"); break;
        }
    } else {
        if (p_ent->level==lev_lang) dbgprintf("LangData");
        else dbgprintf("Data");
    }

    /* entry name/id (non-root entries) */
    ULONG cb;
    if (p_ent->level > lev_root)
    {
        DWORD name = get_32uint_le(&p_ent->dir_ent.Name);
        if (name&IMAGE_RESOURCE_NAME_IS_STRING)
        {
            /* named entry */
            DWORD name_off = name&(~IMAGE_RESOURCE_NAME_IS_STRING);
            ULONG64 name_addr = p_hndl->dir_addr+name_off;

            WORD name_len;
            WCHAR name_buf[0x100];

            if (read_memory(name_addr, &name_len, sizeof(name_len), &cb) &&
                cb==sizeof(name_len))
            {
                update_cstats(p_hndl, p_cstats, rse_name, p_ent->level,
                    ADDR2RVA(name_addr, p_hndl->mod_base),
                    sizeof(name_len)+name_len*sizeof(name_buf[0]));

                name_len = min(name_len, sizeof(name_buf)/sizeof(name_buf[0])-1);
                if (read_memory(name_addr+sizeof(name_len),
                    &name_buf, name_len*sizeof(name_buf[0]), &cb) &&
                    cb==name_len*sizeof(name_buf[0]))
                {
                    IDebugControl4 *DebugControl=NULL;
                    name_buf[name_len] = 0;

                    if ((get_client()->QueryInterface(
                        __uuidof(IDebugControl4), (void **)&DebugControl))==S_OK)
                    {
                        DebugControl->ControlledOutputWide(
                            DBGPRNT_OUTCTL_FLAGS, DBGPRNT_OUTPUT_FLAGS, L" \"%s\"",
                            name_buf);
                        DebugControl->Release();
                    }
                } else {
                    dbgprintf(" ???");
                }
            } else {
                dbgprintf(" ???");
                invalidate_cstats(p_cstats);
            }

            dbgprintf("; name at: 0x%p+0x%04X[0x%08X]", p_hndl->dir_addr,
                name_off, ADDR2RVA(name_addr, p_hndl->mod_base));
        } else
        {
            /* entry with numeric id */
            WORD id = (WORD)name;
            dbgprintf(" #0x%04X", id);

            if (p_ent->level==lev_type)
            {
                const char *pc_tpy_name;
                if (pc_tpy_name=get_rsrctpy_name(id)) dbgprintf(" %s", pc_tpy_name);
            } else
            if (p_ent->level==lev_lang)
            {
                const char *pc_lcid_name;
                if (pc_lcid_name=get_lcid_name(id)) dbgprintf(" %s", pc_lcid_name);
            }
        }
    }
    dbgprintf("\n");

    /* entry details
     */
    if (is_dir)
    {
        /* resource directory */
        IMAGE_RESOURCE_DIRECTORY dir;
        if (read_memory(ent_addr, &dir, sizeof(dir), &cb) && cb==sizeof(dir))
        {
            rsrc_entry_t sub_ent;

            UINT nment_n = get_16uint_le(&dir.NumberOfNamedEntries);
            UINT ident_n = get_16uint_le(&dir.NumberOfIdEntries);

            update_cstats(p_hndl, p_cstats,
                rse_dir, p_ent->level, ADDR2RVA(ent_addr, p_hndl->mod_base),
                sizeof(dir)+(nment_n+ident_n)*sizeof(sub_ent.dir_ent));

            dbgprintf("%s  Characteristics:0x%08X\n",
                spc, get_32uint_le(&dir.Characteristics));
            dbgprintf("%s  Timestamp:      0x%08X\n",
                spc, get_32uint_le(&dir.TimeDateStamp));
            dbgprintf("%s  Major version:  0x%04X\n",
                spc, get_16uint_le(&dir.MajorVersion));
            dbgprintf("%s  Minor version:  0x%04X\n",
                spc, get_16uint_le(&dir.MinorVersion));
            dbgprintf("%s  Total entries:  0x%04X+0x%04X   ; names+ids\n",
                spc, nment_n, ident_n);

            switch (p_ent->level) {
            case lev_root: dbgprintf("%s Types:\n", spc); break;
            case lev_type: dbgprintf("%s Names/IDs:\n", spc); break;
            case lev_name: dbgprintf("%s Instances [per language]:\n", spc); break;
            }

            ULONG64 dir_ent_addr = ent_addr+sizeof(dir);

            p_ent->p_next = &sub_ent;

            for (UINT i=0;
                i<nment_n+ident_n;
                i++, dir_ent_addr+=sizeof(sub_ent.dir_ent))
            {
                if (read_memory(dir_ent_addr, &sub_ent.dir_ent,
                    sizeof(sub_ent.dir_ent), &cb) && cb==sizeof(sub_ent.dir_ent))
                {
                    sub_ent.level = p_ent->level+1;
                    sub_ent.level_i = i+1;
                    sub_ent.p_next = NULL;
                    sub_ent.p_prev = p_ent;

                    print_rsrc_ent(p_hndl, &sub_ent, p_cstats);
                } else {
                    dbgprintf("%s  ???\n", spc);
                    invalidate_cstats(p_cstats);
                }
            }
        } else {
            dbgprintf("%s  ???\n", spc);
            invalidate_cstats(p_cstats);
        }
    } else
    {
        /* resource data entry */
        IMAGE_RESOURCE_DATA_ENTRY dta_ent;
        if (read_memory(ent_addr, &dta_ent, sizeof(dta_ent), &cb) &&
            cb==sizeof(dta_ent))
        {
            update_cstats(p_hndl, p_cstats, rse_dta_ent, p_ent->level,
                ADDR2RVA(ent_addr, p_hndl->mod_base), sizeof(dta_ent));

            DWORD dta_rva = get_32uint_le(&dta_ent.OffsetToData);
            DWORD dta_sz = get_32uint_le(&dta_ent.Size);

            dbgprintf("%s  Data at:  0x%p[0x%08X]\n",
                spc, RVA2ADDR(dta_rva, p_hndl->mod_base), dta_rva);
            dbgprintf("%s  Size:     0x%08X\n", spc, dta_sz);
            dbgprintf("%s  Code page:0x%08X\n",
                spc, get_32uint_le(&dta_ent.CodePage));
            dbgprintf("%s  Reserved: 0x%08X\n",
                spc, get_32uint_le(&dta_ent.Reserved));

            update_cstats(
                p_hndl, p_cstats, rse_dta_inst, p_ent->level, dta_rva, dta_sz);
        } else {
            dbgprintf("%s  ???\n", spc);
            invalidate_cstats(p_cstats);
        }
    }

    return;
}

/* Read resources capacity stats */
static void read_cstats(const prnt_dir_hndl_t *p_hndl,
    const rsrc_entry_t *p_ent, rsrc_cap_stats_t *p_cstats)
{
    ULONG cb;
    BOOL is_dir = TRUE;
    ULONG64 ent_addr = p_hndl->dir_addr;

    if (p_ent->level > lev_root)
    {
        DWORD off_dta = get_32uint_le(&p_ent->dir_ent.OffsetToData);
        is_dir = (off_dta&IMAGE_RESOURCE_DATA_IS_DIRECTORY)!=0;
        off_dta &= ~IMAGE_RESOURCE_DATA_IS_DIRECTORY;
        ent_addr += off_dta;

        DWORD name = get_32uint_le(&p_ent->dir_ent.Name);
        if (name&IMAGE_RESOURCE_NAME_IS_STRING)
        {
            WORD name_len;
            DWORD name_off = name&(~IMAGE_RESOURCE_NAME_IS_STRING);
            ULONG64 name_addr = p_hndl->dir_addr+name_off;

            if (read_memory(name_addr, &name_len, sizeof(name_len), &cb) &&
                cb==sizeof(name_len))
            {
                /* update by the entry name */
                update_cstats(p_hndl, p_cstats, rse_name, p_ent->level,
                    ADDR2RVA(name_addr, p_hndl->mod_base),
                    sizeof(name_len)+name_len*sizeof(WCHAR));
            } else {
                invalidate_cstats(p_cstats);
                goto finish;
            }
        }
    }

    if (is_dir)
    {
        /* resource directory */
        IMAGE_RESOURCE_DIRECTORY dir;
        if (read_memory(ent_addr, &dir, sizeof(dir), &cb) && cb==sizeof(dir))
        {
            rsrc_entry_t sub_ent;

            /* p_prev, p_next, level_i are not used */
            sub_ent.p_prev=NULL;
            sub_ent.p_next=NULL;
            sub_ent.level_i=0;

            UINT nment_n = get_16uint_le(&dir.NumberOfNamedEntries);
            UINT ident_n = get_16uint_le(&dir.NumberOfIdEntries);

            update_cstats(p_hndl, p_cstats, rse_dir, p_ent->level,
                ADDR2RVA(ent_addr, p_hndl->mod_base),
                sizeof(dir)+(nment_n+ident_n)*sizeof(sub_ent.dir_ent));

            ULONG64 dir_ent_addr = ent_addr+sizeof(dir);

            for (UINT i=0;
                i<nment_n+ident_n;
                i++, dir_ent_addr+=sizeof(sub_ent.dir_ent))
            {
                if (read_memory(dir_ent_addr, &sub_ent.dir_ent,
                    sizeof(sub_ent.dir_ent), &cb) &&
                    cb==sizeof(sub_ent.dir_ent))
                {
                    sub_ent.level = p_ent->level+1;
                    read_cstats(p_hndl, &sub_ent, p_cstats);
                    if (p_cstats->b_invalid) break;
                } else {
                    invalidate_cstats(p_cstats);
                    break;
                }
            }
        } else {
            invalidate_cstats(p_cstats);
        }
    } else
    {
        /* resource data entry */
        IMAGE_RESOURCE_DATA_ENTRY dta_ent;
        if (read_memory(ent_addr, &dta_ent, sizeof(dta_ent), &cb) &&
            cb==sizeof(dta_ent))
        {
            update_cstats(p_hndl, p_cstats, rse_dta_ent, p_ent->level,
                ADDR2RVA(ent_addr, p_hndl->mod_base), sizeof(dta_ent));

            DWORD dta_rva = get_32uint_le(&dta_ent.OffsetToData);
            DWORD dta_sz = get_32uint_le(&dta_ent.Size);

            update_cstats(
                p_hndl, p_cstats, rse_dta_inst, p_ent->level, dta_rva, dta_sz);
        } else {
            invalidate_cstats(p_cstats);
        }
    }

finish:
    return;
}

/* exported; see header for details */
void print_rsrc(ULONG64 mod_base, const rng_spec_t *p_rng, DWORD flags)
{
    prnt_dir_hndl_t hndl;
    if (!init_prnt_dir_hndl(
        &hndl, mod_base, IMAGE_DIRECTORY_ENTRY_RESOURCE, p_rng)) goto finish;

    BOOL b_capas = (flags&PRNTRSRC_CAPAS)!=0;
    BOOL b_capas_only = (flags&PRNTRSRC_CAPAS_ONLY)!=0;

    /* print header */
    if (!hndl.dir_addr || (!p_rng && !hndl.dir_sz)) {
        info_dbgprintf("No resources in this module!\n");
        goto finish;
    } else
        info_dbgprintf("Resorces at: 0x%p\n", hndl.dir_addr);

    if (!b_capas_only) {
        info_dbgprintf("RVA provided in [], '#' precedes numeric ids\n\n");
    }

    rsrc_entry_t root_ent;
    init_root_ent(&root_ent);

    rsrc_cap_stats_t cstats;
    init_cstats(&cstats);

    if (b_capas_only) {
        read_cstats(&hndl, &root_ent, &cstats);
    } else {
        print_rsrc_ent(&hndl, &root_ent, (b_capas ? &cstats : NULL));
        dbgprintf("\n");
    }

    if (b_capas || b_capas_only)
    {
        if (!cstats.b_invalid) {
            info_dbgprintf("Resources contained in section(s):");
            for (UINT i=0; i<cstats.n_sects; i++)
                dbgprintf("%c%d", (i==0 ? ' ' : ','), cstats.sects[i]+1);
            dbgprintf("\n");

            info_dbgprintf("Total size: 0x%08X, word-padded: 0x%08X, "
                "dword-padded: 0x%08X\n", cstats.total_sz.no_padd,
                cstats.total_sz.w_padd, cstats.total_sz.dw_padd);

            if (cstats.b_out_sscope) {
                warn_dbgprintf(
                    "Resources contain elements outside module's sections!\n");
            }
        } else {
            warn_dbgprintf("Can not establish resources capacity\n");
        }
    }

    free_cstats(&cstats);

finish:
    return;
}

/* Initialize print dir handle of resource dir from rsrc fix handle */
static inline void init_prnt_dir_hndl(
    prnt_dir_hndl_t *p_hndl, const rsrc_fix_hndl_t *p_fix_hndl)
{
    p_hndl->mod_base = p_fix_hndl->mod_base;
    p_hndl->nt_hdrs = p_fix_hndl->nt_hdrs;

    p_hndl->n_sects = p_fix_hndl->n_sects;
    memcpy(p_hndl->sectab, p_fix_hndl->sectab,
        p_fix_hndl->n_sects*sizeof(p_fix_hndl->sectab[0]));

    p_hndl->dir_id = IMAGE_DIRECTORY_ENTRY_RESOURCE;
    p_hndl->dir_addr = p_fix_hndl->src_rsrc_addr;
    p_hndl->dir_sz = p_fix_hndl->dir_rsrc_sz;
}

/* Free fix resources handle */
static void free_rsrc_fix_hndl(rsrc_fix_hndl_t *p_hndl, BOOL b_always_rem)
{
    free_cstats(&p_hndl->cstats);

    if (p_hndl->fh)
    {
        fclose(p_hndl->fh);
        p_hndl->fh=NULL;

        if (b_always_rem || !GetPrivateProfileInt(
            PROP_SECT_RSRCFIX, PROP_RSRCFIX_KEEP_TMPFILE, 0, PROP_FILE))
        {
            remove(p_hndl->fname);
        } else {
            info_dbgprintf(
                "Temporary file with recovered resources [%s] not deleted\n",
                p_hndl->fname);
        }
    }
}

/* init_rsrc_fix_hndl() ret codes */
typedef enum _init_rsrc_fix_rc_t
{
    initrsrc_ok=0,
    initrsrc_not_req,   /* fixing not required */
    initrsrc_no_rsrc,   /* no resources - nothing to fix */
    initrsrc_err        /* error */
} init_rsrc_fix_rc_t;

/* Initialize fix resources handle */
static init_rsrc_fix_rc_t init_rsrc_fix_hndl(
    rsrc_fix_hndl_t *p_hndl, const dump_pe_hndl_t *p_dpe_hndl)
{
    init_rsrc_fix_rc_t ret=initrsrc_ok;

    memset(p_hndl, 0, sizeof(*p_hndl));
    init_cstats(&p_hndl->cstats);

    /* check if fix was requested */
    char prm_val[20];
    if (GetPrivateProfileString(PROP_SECT_RSRCFIX, PROP_RSRCFIX_RECOVER,
        "", prm_val, sizeof(prm_val), PROP_FILE)<=0) *prm_val=0;

    rsrcrv_val_t rsrcrv = (rsrcrv_val_t)get_ht_num(
        RSRCRVVALS_HT, NUM_RSRCRVVALS, (*prm_val ? prm_val : NULL), rsrcrv_no);
    if (rsrcrv==rsrcrv_no) {
        ret=initrsrc_not_req;
        goto finish;
    }

    p_hndl->mod_base = p_dpe_hndl->mod_base;
    p_hndl->nt_hdrs = p_dpe_hndl->nt_hdrs;

    p_hndl->n_sects = p_dpe_hndl->n_sects;
    memcpy(p_hndl->sectab, p_dpe_hndl->sectab,
        p_dpe_hndl->n_sects*sizeof(p_dpe_hndl->sectab[0]));

    IMAGE_DATA_DIRECTORY *p_rd;
    if (!get_data_dir(
        &p_hndl->nt_hdrs, IMAGE_DIRECTORY_ENTRY_RESOURCE, &p_rd, FALSE))
    {
        info_dbgprintf("No resources dir in this module; nothing to fix\n");
        ret=initrsrc_no_rsrc;
        goto finish;
    }

    p_hndl->dir_rsrc_sz = get_32uint_le(&p_rd->Size);

    /* update resources src/dst addr */
    p_hndl->src_rsrc_addr = p_hndl->dst_rsrc_addr =
        RVA2ADDR(get_32uint_le(&p_rd->VirtualAddress), p_hndl->mod_base);

    DWORD src_rva = GetPrivateProfileInt(
        PROP_SECT_RSRCFIX, PROP_RSRCFIX_RSRC_RVA, -1, PROP_FILE);
    if (src_rva!=(DWORD)-1)
        p_hndl->src_rsrc_addr = RVA2ADDR(src_rva, p_hndl->mod_base);

    if (!p_hndl->dst_rsrc_addr || !p_hndl->src_rsrc_addr)
    {
        info_dbgprintf("No resources in this module; nothing to fix\n");
        ret=initrsrc_no_rsrc;
        goto finish;
    }

    /* initialize and read capacity stats */
    prnt_dir_hndl_t prnt_hndl;
    init_prnt_dir_hndl(&prnt_hndl, p_hndl);

    rsrc_entry_t root_ent;
    init_root_ent(&root_ent);

    read_cstats(&prnt_hndl, &root_ent, &p_hndl->cstats);
    if (p_hndl->cstats.b_invalid) {
        err_dbgprintf("Can not establish resources capacity\n");
        ret=initrsrc_err;
        goto finish;
    }

    if (rsrcrv==rsrcrv_detect &&
        p_hndl->cstats.n_sects<=1 && !p_hndl->cstats.b_out_sscope)
    {
        info_dbgprintf(
            "No scattered resources across sections; no need to recovery\n");
        ret=initrsrc_not_req;
        goto finish;
    }

    /* get padding config */
    if (GetPrivateProfileString(PROP_SECT_RSRCFIX, PROP_RSRCFIX_PADD,
        "", prm_val, sizeof(prm_val), PROP_FILE)<=0) *prm_val=0;

    p_hndl->padd = (padd_val_t)get_ht_num
        (PADDVALS_HT, NUM_PADDVALS, (*prm_val ? prm_val : NULL), padd_auto);

    /* update recovered resources size */
    info_dbgprintf("Resources recovery with ");
    switch (p_hndl->padd)
    {
    case padd_no:
        p_hndl->rcv_rsrc_sz = p_hndl->cstats.total_sz.no_padd;
        dbgprintf("no padding\n");
        break;
    case padd_w:
        p_hndl->rcv_rsrc_sz = p_hndl->cstats.total_sz.w_padd;
        dbgprintf("word padding\n");
        break;
    case padd_dw:
        p_hndl->rcv_rsrc_sz = p_hndl->cstats.total_sz.dw_padd;
        dbgprintf("dword padding\n");
        break;
    case padd_auto:
        if (p_hndl->dir_rsrc_sz >= p_hndl->cstats.total_sz.dw_padd) {
            p_hndl->padd = padd_dw;
            p_hndl->rcv_rsrc_sz = p_hndl->cstats.total_sz.dw_padd;
            dbgprintf("dword padding (auto detected)\n");
        } else
        if (p_hndl->dir_rsrc_sz >= p_hndl->cstats.total_sz.w_padd) {
            p_hndl->padd = padd_w;
            p_hndl->rcv_rsrc_sz = p_hndl->cstats.total_sz.w_padd;
            dbgprintf("word padding (auto detected)\n");
        } else
        if (p_hndl->dir_rsrc_sz >= p_hndl->cstats.total_sz.no_padd) {
            p_hndl->padd = padd_no;
            p_hndl->rcv_rsrc_sz = p_hndl->cstats.total_sz.no_padd;
            dbgprintf("no padding (auto detected)\n");
        } else {
            err_dbgprintf("Can not detect proper size of resources padding due "
                "to unsufficient resources directory size!\n");
            ret=initrsrc_err;
            goto finish;
        }
        break;
    }

    /* set resource offsets of the following layout:
       1. dirs (level 0,1,...)
       2. data entries
       3. names
       4. data instances
     */
    DWORD off=0;
    for (UINT i=0; i<p_hndl->cstats.dir_szs_sz &&
        p_hndl->cstats.p_dir_szs[i].no_padd; i++)
    {
        p_hndl->cstats.p_dir_szs[i].off=off;
        off += (p_hndl->padd==padd_no ? p_hndl->cstats.p_dir_szs[i].no_padd :
            (p_hndl->padd==padd_w ? p_hndl->cstats.p_dir_szs[i].w_padd :
            p_hndl->cstats.p_dir_szs[i].dw_padd));
    }

    p_hndl->cstats.dta_ent_sz.off=off;
    off += (p_hndl->padd==padd_no ? p_hndl->cstats.dta_ent_sz.no_padd :
        (p_hndl->padd==padd_w ? p_hndl->cstats.dta_ent_sz.w_padd :
        p_hndl->cstats.dta_ent_sz.dw_padd));

    p_hndl->cstats.name_sz.off=off;
    off += (p_hndl->padd==padd_no ? p_hndl->cstats.name_sz.no_padd :
        (p_hndl->padd==padd_w ? p_hndl->cstats.name_sz.w_padd :
        p_hndl->cstats.name_sz.dw_padd));

    p_hndl->cstats.dta_inst_sz.off=off;
    off += (p_hndl->padd==padd_no ? p_hndl->cstats.dta_inst_sz.no_padd :
        (p_hndl->padd==padd_w ? p_hndl->cstats.dta_inst_sz.w_padd :
        p_hndl->cstats.dta_inst_sz.dw_padd));

    /* open rsrc tmp file as the output */
    if (!GetPrivateProfileString(PROP_SECT_RSRCFIX, PROP_RSRCFIX_TMPFILE,
        "", p_hndl->fname, sizeof(p_hndl->fname), PROP_FILE))
    {
        if (GetTempPath(sizeof(p_hndl->fname), p_hndl->fname)<=0) {
            err_dbgprintf(
                "Can not establish temporary path to locate resources tmp file\n");
            ret=initrsrc_err;
            goto finish;
        }
        p_hndl->fname[MAX_PATH]=0;

        strncat(p_hndl->fname, OUT_TMP_RSRC_DEF_FILE, sizeof(p_hndl->fname));
        p_hndl->fname[MAX_PATH]=0;
    } else p_hndl->fname[MAX_PATH]=0;

    p_hndl->fh = fopen(p_hndl->fname, "wb+");
    if (!p_hndl->fh) {
        err_dbgprintf("Can not open resources tmp file [%s]: %s\n",
            p_hndl->fname, strerror(errno));
        ret=initrsrc_err;
        goto finish;
    }

finish:
    if (ret!=initrsrc_ok) free_rsrc_fix_hndl(p_hndl, TRUE);
    return ret;
}

/* Depending on padding round-up the value 'val' */
static inline ULONG get_padded_val(const rsrc_fix_hndl_t *p_hndl, ULONG val)
{
    return (p_hndl->padd==padd_no ? val :
        (p_hndl->padd==padd_w ? RNDUP_W(val) : RNDUP_DW(val)));
}

/* Set file ptr to 'fptr' */
static BOOL set_fptr(const rsrc_fix_hndl_t *p_hndl, DWORD fptr)
{
    BOOL ret=FALSE;
    if (!fseek(p_hndl->fh, 0, SEEK_END))
    {
        DWORD curr_pos = ftell(p_hndl->fh);
        if (curr_pos!=(DWORD)-1L)
        {
            if (fptr<curr_pos) {
                ret = !fseek(p_hndl->fh, fptr, SEEK_SET);
            } else {
                for (; curr_pos<fptr; curr_pos++) {
                    if (fputc(0, p_hndl->fh)==EOF) break;
                }
                if (curr_pos>=fptr) ret=TRUE;
            }
        }
    }
    return ret;
}

/* write padding with length 'len' */
static inline BOOL write_padd(const rsrc_fix_hndl_t *p_hndl, ULONG len) {
    for (; len; len--) if (fputc(0, p_hndl->fh)==EOF) return FALSE;
    return TRUE;
}

/* fix resource entry */
static BOOL fix_rsrc_ent(rsrc_fix_hndl_t *p_hndl, const rsrc_entry_t *p_ent)
{
    BOOL ret=FALSE, b_ferr=FALSE;

    ULONG cb;
    BOOL is_dir = TRUE;
    ULONG64 ent_addr = p_hndl->src_rsrc_addr;

    if (p_ent->level > lev_root)
    {
        DWORD off_dta = get_32uint_le(&p_ent->dir_ent.OffsetToData);
        is_dir = (off_dta&IMAGE_RESOURCE_DATA_IS_DIRECTORY)!=0;
        off_dta &= ~IMAGE_RESOURCE_DATA_IS_DIRECTORY;
        ent_addr += off_dta;

        DWORD name = get_32uint_le(&p_ent->dir_ent.Name);
        if (name&IMAGE_RESOURCE_NAME_IS_STRING)
        {
            WORD name_len;
            DWORD name_off = name&(~IMAGE_RESOURCE_NAME_IS_STRING);
            ULONG64 name_addr = p_hndl->src_rsrc_addr+name_off;

            if (read_memory(name_addr, &name_len, sizeof(name_len), &cb) &&
                cb==sizeof(name_len))
            {
                /* write name */
                if (b_ferr=!set_fptr(p_hndl, p_hndl->cstats.name_sz.off))
                    goto finish;

                ULONG n = sizeof(name_len)+name_len*sizeof(WCHAR);
                ULONG pdn = get_padded_val(p_hndl, n);
                p_hndl->cstats.name_sz.off += pdn;

                cpy_ret_t rc = mem2file(p_hndl->fh, name_addr, n);
                if (rc!=cpy_ok) { b_ferr=(rc==cpy_dst_err); goto finish; }
                if (b_ferr=!write_padd(p_hndl, pdn-n)) goto finish;
            } else goto finish;
        }
    }

    if (is_dir)
    {
        /* resource directory */
        IMAGE_RESOURCE_DIRECTORY dir;
        if (read_memory(ent_addr, &dir, sizeof(dir), &cb) && cb==sizeof(dir))
        {
            rsrc_entry_t sub_ent;

            /* p_prev, p_next, level_i are not used */
            sub_ent.p_prev=NULL;
            sub_ent.p_next=NULL;
            sub_ent.level_i=0;

            UINT nment_n = get_16uint_le(&dir.NumberOfNamedEntries);
            UINT ident_n = get_16uint_le(&dir.NumberOfIdEntries);

            ULONG64 dir_ent_addr = ent_addr+sizeof(dir);

            /* write dir */
            if (b_ferr=!set_fptr(p_hndl,
                p_hndl->cstats.p_dir_szs[p_ent->level].off)) goto finish;

            ULONG n = sizeof(dir);
            p_hndl->cstats.p_dir_szs[p_ent->level].off += sizeof(dir);

            if (b_ferr=(fwrite(&dir, 1, sizeof(dir), p_hndl->fh)!=sizeof(dir)))
                goto finish;

            /* write dir entries */
            for (UINT i=0;
                i<nment_n+ident_n;
                i++, dir_ent_addr+=sizeof(sub_ent.dir_ent))
            {
                if (read_memory(dir_ent_addr, &sub_ent.dir_ent,
                    sizeof(sub_ent.dir_ent), &cb) && cb==sizeof(sub_ent.dir_ent))
                {
                    /* remember current offset since they
                       are modified by the recursive call */
                    DWORD name_off = p_hndl->cstats.name_sz.off;
                    DWORD dir_sublev_off =
                        p_hndl->cstats.p_dir_szs[p_ent->level+1].off;
                    DWORD dta_ent_off = p_hndl->cstats.dta_ent_sz.off;

                    sub_ent.level = p_ent->level+1;
                    if (!fix_rsrc_ent(p_hndl, &sub_ent)) goto finish;

                    IMAGE_RESOURCE_DIRECTORY_ENTRY sub_dir_ent=sub_ent.dir_ent;

                    if (get_32uint_le(&sub_dir_ent.Name) &
                        IMAGE_RESOURCE_NAME_IS_STRING)
                    {
                        set_32uint_le(&sub_dir_ent.Name,
                            IMAGE_RESOURCE_NAME_IS_STRING | name_off);
                    }

                    if (get_32uint_le(&sub_dir_ent.OffsetToData) &
                        IMAGE_RESOURCE_DATA_IS_DIRECTORY)
                    {
                        set_32uint_le(&sub_dir_ent.OffsetToData,
                            IMAGE_RESOURCE_DATA_IS_DIRECTORY | dir_sublev_off);
                    } else {
                        set_32uint_le(&sub_dir_ent.OffsetToData, dta_ent_off);
                    }

                    if (b_ferr=!set_fptr(p_hndl,
                        p_hndl->cstats.p_dir_szs[p_ent->level].off))
                            goto finish;

                    n += sizeof(sub_dir_ent);
                    p_hndl->cstats.p_dir_szs[p_ent->level].off += sizeof(sub_dir_ent);

                    if (b_ferr=(fwrite(&sub_dir_ent, 1,
                        sizeof(sub_dir_ent), p_hndl->fh)!=sizeof(sub_dir_ent)))
                            goto finish;
                } else
                    goto finish;
            }

            /* finally write padding for the whole set: dir + its entries */
            ULONG pdn = get_padded_val(p_hndl, n);
            p_hndl->cstats.p_dir_szs[p_ent->level].off += pdn-n;
            if (b_ferr=!write_padd(p_hndl, pdn-n)) goto finish;

        } else
            goto finish;
    } else
    {
        /* resource data entry */
        IMAGE_RESOURCE_DATA_ENTRY dta_ent;
        if (read_memory(ent_addr, &dta_ent, sizeof(dta_ent), &cb) &&
            cb==sizeof(dta_ent))
        {
            DWORD dta_rva = get_32uint_le(&dta_ent.OffsetToData);
            DWORD dta_sz = get_32uint_le(&dta_ent.Size);

            /* write data entry */
            set_32uint_le(&dta_ent.OffsetToData,
                ADDR2RVA(p_hndl->dst_rsrc_addr+p_hndl->cstats.dta_inst_sz.off,
                p_hndl->mod_base));

            if (b_ferr=!set_fptr(p_hndl, p_hndl->cstats.dta_ent_sz.off))
                goto finish;

            ULONG n = sizeof(dta_ent);
            ULONG pdn = get_padded_val(p_hndl, n);
            p_hndl->cstats.dta_ent_sz.off += pdn;

            if (b_ferr=(fwrite(&dta_ent, 1, n, p_hndl->fh)!=n)) goto finish;
            if (b_ferr=!write_padd(p_hndl, pdn-n)) goto finish;

            /* ... and the data instance itself */
            if (b_ferr=!set_fptr(p_hndl, p_hndl->cstats.dta_inst_sz.off))
                goto finish;

            n = dta_sz;
            pdn = get_padded_val(p_hndl, n);
            p_hndl->cstats.dta_inst_sz.off += pdn;

            cpy_ret_t rc = mem2file(
                p_hndl->fh, RVA2ADDR(dta_rva, p_hndl->mod_base), n);
            if (rc!=cpy_ok) { b_ferr=(rc==cpy_dst_err); goto finish; }
            if (b_ferr=!write_padd(p_hndl, pdn-n)) goto finish;
        } else goto finish;
    }

    ret=TRUE;
finish:
    if (b_ferr) err_dbgprintf("Resources tmp file access error\n");
    return ret;
}

/* exported; see header for details */
BOOL fix_rsrc(const dump_pe_hndl_t *p_hndl)
{
    BOOL ret=FALSE, b_always_rem=TRUE;

    rsrc_fix_hndl_t fix_hndl;
    init_rsrc_fix_rc_t rc = init_rsrc_fix_hndl(&fix_hndl, p_hndl);

    if (rc==initrsrc_not_req || rc==initrsrc_no_rsrc) goto no_err;
    else
    if (rc!=initrsrc_ok) goto err;

    /* some integrity checks */
    DWORD dst_rsrc_rptr, rsrc_n_raw_rem;
    if (!get_raw_ptr(p_hndl, ADDR2RVA(fix_hndl.dst_rsrc_addr, fix_hndl.mod_base),
        &dst_rsrc_rptr, &rsrc_n_raw_rem, NULL) || !dst_rsrc_rptr)
    {
        err_dbgprintf("Destination resources addres 0x%p "
            "outside PE sections raw image\n", fix_hndl.dst_rsrc_addr);
        goto err;
    }
    if (fix_hndl.rcv_rsrc_sz > rsrc_n_raw_rem) {
        err_dbgprintf("Recovered resources sticks out 0x%04X bytes beyond "
            "its section's raw size\n", fix_hndl.rcv_rsrc_sz-rsrc_n_raw_rem);
        goto err;
    }
    if (fix_hndl.rcv_rsrc_sz > fix_hndl.dir_rsrc_sz) {
        warn_dbgprintf("Recovered resources size [0x%08X] "
            "exceeds resources dir size [0x%08X]\n",
            fix_hndl.rcv_rsrc_sz, fix_hndl.dir_rsrc_sz);
    }

    /* fix resources (starting from root ent) */
    rsrc_entry_t root_ent;
    init_root_ent(&root_ent);

    if (!fix_rsrc_ent(&fix_hndl, &root_ent)) goto err;
    b_always_rem=FALSE;

    /* copy result to the final dump file */
    if (fflush(fix_hndl.fh) ||
        fseek(fix_hndl.fh, 0, SEEK_SET) ||
        fseek(p_hndl->f_out, dst_rsrc_rptr, SEEK_SET) ||
        file2file(p_hndl->f_out, fix_hndl.fh, 0)!=cpy_ok)
    {
        err_dbgprintf("Copying resources tmp file error\n");
        goto err;
    }

    /* finally update the dumped PE resource dir */
    DWORD dirs_rptr = get_32uint_le(&p_hndl->dos_hdr.e_lfanew) +
        (UINT8*)(p_hndl->nt_hdrs.pe_tpy==pe_32bit ?
        &p_hndl->nt_hdrs.hdr.pe32.OptionalHeader.DataDirectory[0] :
        &p_hndl->nt_hdrs.hdr.pe64.OptionalHeader.DataDirectory[0]) -
        (UINT8*)&(p_hndl->nt_hdrs.hdr);

    DWORD dd_rsrc_rptr = dirs_rptr +
        IMAGE_DIRECTORY_ENTRY_RESOURCE*sizeof(IMAGE_DATA_DIRECTORY);

    IMAGE_DATA_DIRECTORY *p_rd;
    /* will always success */
    get_data_dir(&p_hndl->nt_hdrs, IMAGE_DIRECTORY_ENTRY_RESOURCE, &p_rd, FALSE);

    set_32uint_le(&p_rd->Size, fix_hndl.rcv_rsrc_sz);

    if (!fseek(p_hndl->f_out, dd_rsrc_rptr, SEEK_SET) &&
        fwrite(p_rd, 1, sizeof(*p_rd), p_hndl->f_out)==sizeof(*p_rd))
    {
        info_dbgprintf(
            "Resources have been patched; size: 0x%08X\n", fix_hndl.rcv_rsrc_sz);
    } else {
        err_dbgprintf(
            "Error occurred during updating resources size in PE directory\n");
        goto err;
    }

no_err:
    ret=TRUE;
err:
    free_rsrc_fix_hndl(&fix_hndl, b_always_rem);
    return ret;
}
