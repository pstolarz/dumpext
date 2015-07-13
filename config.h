/*
   Copyright (c) 2015 Piotr Stolarz
   dumpext: PE files fix, dump & analysis WinDbg extension

   Distributed under the GNU General Public License (the License)
   see accompanying file LICENSE for details.

   This software is distributed WITHOUT ANY WARRANTY; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the License for more information.
 */

#ifndef __DUMPEXT_CONFIG_H__
#define __DUMPEXT_CONFIG_H__

/* property file */
extern const char *PROP_FILE;

/* extension dll home path */
extern const char *HOME_PATH;

extern const char *PROP_SECT_OPTH;
extern const char *PROP_OPTH_ENTRY_POINT;
extern const char *PROP_OPTH_BASE_CODE;
extern const char *PROP_OPTH_BASE_DATA;

extern const char *PROP_SECT_DIRS;
extern const char *PROP_DIRS_EXP_RVA;
extern const char *PROP_DIRS_EXP_SZ;
extern const char *PROP_DIRS_IDT_RVA;
extern const char *PROP_DIRS_IDT_SZ;
extern const char *PROP_DIRS_RSRC_RVA;
extern const char *PROP_DIRS_RSRC_SZ;
extern const char *PROP_DIRS_EXPT_RVA;
extern const char *PROP_DIRS_EXPT_SZ;
extern const char *PROP_DIRS_CERT_RVA;
extern const char *PROP_DIRS_CERT_SZ;
extern const char *PROP_DIRS_RELOC_RVA;
extern const char *PROP_DIRS_RELOC_SZ;
extern const char *PROP_DIRS_DBG_RVA;
extern const char *PROP_DIRS_DBG_SZ;
extern const char *PROP_DIRS_ARCH_RVA;
extern const char *PROP_DIRS_ARCH_SZ;
extern const char *PROP_DIRS_GPTR_RVA;
extern const char *PROP_DIRS_GPTR_SZ;
extern const char *PROP_DIRS_TLS_RVA;
extern const char *PROP_DIRS_TLS_SZ;
extern const char *PROP_DIRS_CFG_RVA;
extern const char *PROP_DIRS_CFG_SZ;
extern const char *PROP_DIRS_BOUND_RVA;
extern const char *PROP_DIRS_BOUND_SZ;
extern const char *PROP_DIRS_IAT_RVA;
extern const char *PROP_DIRS_IAT_SZ;
extern const char *PROP_DIRS_DELAY_RVA;
extern const char *PROP_DIRS_DELAY_SZ;
extern const char *PROP_DIRS_CLR_RVA;
extern const char *PROP_DIRS_CLR_SZ;

extern const char *PROP_SECT_SECTS;
extern const char *PROP_SECTS_DEL_TRAILING_SECS;
extern const char *PROP_SECTS_NAME;
extern const char *PROP_SECTS_CHARACTER;
extern const char *PROP_SECTS_VSZ;
extern const char *PROP_SECTS_RVA;
extern const char *PROP_SECTS_RSZ;
extern const char *PROP_SECTS_DMPCONT;

extern const char *PROP_SECT_IMPFIX;
extern const char *PROP_IMPFIX_NO_PADD_NAMES;
extern const char *PROP_IMPFIX_NO_ILTS;
extern const char *PROP_IMPFIX_HN_TAB_RVA;
extern const char *PROP_IMPFIX_NAME_TAB_RVA;

extern const char *PROP_SECT_DUMP;
extern const char *PROP_DUMP_OUTPUT;
extern const char *PROP_DUMP_SET_CRC;
extern const char *PROP_DUMP_SAVE_HDR_SPACE;
extern const char *PROP_DUMP_BIND_IMPORTS;

extern const char *PROP_SECT_CONFLSPEC;

extern const char *PROP_SECT_IMPSPEC;
extern const char *PROP_IMPSPEC_IAT_RVA;

extern const char *PROP_SECT_RSRCFIX;
extern const char *PROP_RSRCFIX_RECOVER;
extern const char *PROP_RSRCFIX_RSRC_RVA;
extern const char *PROP_RSRCFIX_PADD;
extern const char *PROP_RSRCFIX_TMPFILE;
extern const char *PROP_RSRCFIX_KEEP_TMPFILE;

extern const char *OUT_DUMP_DEF_FILE;
extern const char *OUT_TMP_RSRC_DEF_FILE;

extern const char *IDT_AFTER_IAT;
extern const char *RSZ_AS_VSZ;
extern const char *RSZ_AUTO;

extern const char *DMPCONT_MEM;
extern const char *DMPCONT_ZEROS;
extern const char *DMPCONT_FILE;


typedef struct _str_num_t
{
    char *str;
    DWORD num;
} str_num_t;

typedef enum _set_val_t
{
    set_no=0,
    set_as_original,
    set_always
} set_val_t;

typedef enum _rsrcrv_val_t
{
    rsrcrv_no=0,
    rsrcrv_yes,
    rsrcrv_detect
} rsrcrv_val_t;

typedef enum _padd_val_t
{
    padd_no=0,
    padd_w,
    padd_dw,
    padd_auto
} padd_val_t;

extern const size_t NUM_SETVALS;
extern const str_num_t *SETVALS_HT;

extern const size_t NUM_RSRCRVVALS;
extern const str_num_t *RSRCRVVALS_HT;

extern const size_t NUM_PADDVALS;
extern const str_num_t *PADDVALS_HT;

extern const size_t NUM_SECCHRVALS;
extern const str_num_t *SECCHRVALS_HT;

extern const size_t NUM_FLCHRVALS;
extern const str_num_t *FLCHRVALS_HT;

extern const size_t NUM_DLLCHRVALS;
extern const str_num_t *DLLCHRVALS_HT;

extern const size_t NUM_MEMINFOVALS;
extern const str_num_t *MEMINFOVALS_HT;

/* Get 'num' field from a string-num hash table pointed by 'ht' with 'ht_sz'
   elements. 'str' acts as a searching key in the table. The comparison is
   case insensitive. If the 'str' is not found the 'def_val' is returned.
 */
DWORD get_ht_num(
    const str_num_t *ht, size_t ht_sz, const char *str, DWORD def_val);

/* Get 'str' field from a string-num hash table pointed by 'ht' with 'ht_sz'
   elements. 'num' acts as a searching key in the table. If the 'num' is not
   found the 'def_val' is returned.
 */
const char *get_ht_str(
    const str_num_t *ht, size_t ht_sz, DWORD num, const char *def_val);

/* Print max 32-bit flags in the config file format */
void print_flags(const str_num_t *ht, size_t ht_sz, DWORD flags, UINT bits);

/* Parse max 32-bit flags in the config file format
   NOTE: 'pc_flags' string buf is modified during parsing
 */
DWORD parse_flags(const str_num_t *ht, size_t ht_sz, char *pc_flags);

/* Initialize configuration */
void init_config(HINSTANCE hinstDLL);

/* Set the property file */
void set_prop_file(const char* pc_prop_file);

#endif /* __DUMPEXT_CONFIG_H__ */
