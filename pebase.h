/*
   Copyright (c) 2015 Piotr Stolarz
   dumpext: PE files fix, dump & analysis WinDbg extension

   Distributed under the GNU General Public License (the License)
   see accompanying file LICENSE for details.

   This software is distributed WITHOUT ANY WARRANTY; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the License for more information.
 */

#ifndef __DUMPEXT_PEBASE_H__
#define __DUMPEXT_PEBASE_H__

/* max number of section in PE file (Windows specific) */
#define MAX_SECTIONS        96

/* supported PE formats */
typedef enum _pe_header_type_t
{
    pe_32bit,
    pe_64bit
} pe_header_type_t;

typedef struct _image_nt_headers_t
{
    pe_header_type_t pe_tpy;

    union {
        IMAGE_NT_HEADERS32 pe32;    /* pe_32bit */
        IMAGE_NT_HEADERS64 pe64;    /* pe_64bit */
    } hdr;
} image_nt_headers_t;

/* macros for accessing common PE32/PE32+
   headers' components: 'Signature' and 'FileHeader' */
#define get_Signature(h)  ((h)->hdr.pe32.Signature)
#define get_FileHeader(h) ((h)->hdr.pe32.FileHeader)

typedef enum _sect_dump_tpy_t
{
    secdmp_mem=0,   /* dump sect from memory */
    secdmp_zeros,   /* fill sect with zeros while dump */
    secdmp_file     /* init sect with file content while dump */
} sect_dump_tpy_t;

/* struc of internal handle used by dump pe funcs */
typedef struct _dump_pe_hndl_t
{
    ULONG64 mod_base;
    FILE *f_out;                    /* output dump file handle */
    char f_out_name[MAX_PATH+1];    /* ... and its name */

    /* module's headers */
    IMAGE_DOS_HEADER dos_hdr;
    image_nt_headers_t nt_hdrs;

    /* sections table */
    DWORD n_sects;
    IMAGE_SECTION_HEADER sectab[MAX_SECTIONS];

    /* debug dir data (if need to be modified) */
    ULONG64 debug_addr;             /* 0 if debug data need not to be modified;
                                       the original data is taken */
    IMAGE_DEBUG_DIRECTORY debug;    /* debug dir data */

    struct
    {
        sect_dump_tpy_t tpy;

        /* 'secdmp_file' type only */
        struct
        {
            FILE *fh;   /* file handle */
            ULONG fsz;  /* file size */
        } dmpfile;
    } sect_dmpcfg[MAX_SECTIONS];
} dump_pe_hndl_t;

/* print PE dir details handle */
typedef struct _prnt_dir_hndl_t
{
    ULONG64 mod_base;
    image_nt_headers_t nt_hdrs;

    /* sections table */
    DWORD n_sects;
    IMAGE_SECTION_HEADER sectab[MAX_SECTIONS];

    ULONG dir_id;
    ULONG64 dir_addr;           /* dir addr as taken from the dir table */
    DWORD dir_sz;               /* dir size as taken from the dir table */
} prnt_dir_hndl_t;


#define RVA2ADDR(rva,mb) ((rva) ? ((rva)+(mb)) : 0)
#define ADDR2RVA(adr,mb) ((DWORD)((adr) ? ((adr)-(mb)) : 0))

/* Read DOS & NT headers for a module with base 'mod_base'. Write them under
   'p_dos_hdr' & 'p_nt_hdrs'. If 'p_sectab_addr' is not NULL the address of the
   section table will be written under the pointer. If 'b_logs' is TRUE print
   error info. Returns TRUE for success.
 */
BOOL read_pe_headers(ULONG64 mod_base, IMAGE_DOS_HEADER *p_dos_hdr,
    image_nt_headers_t *p_nt_hdrs, ULONG64 *p_sectab_addr, BOOL b_logs);

/* Read sections table located under address 'sectab_addr'. The sections are
   written under 'p_sectab' as read from the PE file. The table must have at
   least MAX_SECTIONS positions. Number of sections is returned. 0 means no
   sections or error. If 'b_fix_empty_rng' is TRUE the function fixes malformed
   empty ranges.
 */
DWORD read_sectab(const image_nt_headers_t *p_nt_hdrs, ULONG64 sectab_addr,
    IMAGE_SECTION_HEADER *p_sectab, BOOL b_fix_empty_rng, BOOL b_logs);

/* Find a data directory entry 'dir_id' in the optional header and write its
   address under 'pp_dir_entry'. If 'b_logs' is TRUE print error info. Returns
   TRUE for success.
 */
BOOL get_data_dir(const image_nt_headers_t *p_nt_hdrs, UINT dir_id,
    IMAGE_DATA_DIRECTORY **pp_dir_entry, BOOL b_logs);

/* The func returns some info about 'rva' address basing on the section table
   pointed by 'p_sectab' and 'n_sects' number of sections. The following info is
   returned:
   - number of rva's owning section index (0 based): 'p_sect_i'. Always set if
     the func returns TRUE.
   - number of remaining bytes from 'rva' to the end of the owning section's raw
     data: 'p_n_raw_rem'. May be zero if the rva is behind the section's raw data.
   - number of remaining bytes from 'rva' to the end of the owning section's
     data: 'p_n_va_rem'. Always set to a positive value if the func returns TRUE.
   - raw pointer (file pointer) of the RVA: 'p_rptr'. May be zero if the rva is
     behind the section's raw data.
    Returns TRUE if an owning section's of 'rva' has been found, FALSE otherwise.
 */
BOOL get_rva_info(const IMAGE_SECTION_HEADER *p_sectab, DWORD n_sects, DWORD rva,
    DWORD *p_sect_i, DWORD *p_n_raw_rem, DWORD *p_n_va_rem, DWORD *p_rptr);

/* The func returns some info about 'rptr' pointer to raw data basing on the
   section table pointed by 'p_sectab' and 'n_sects' number of sections. The
   following info is returned:
   - number of rptr's owning section index (0 based): 'p_sect_i'. Always set if
     the function returns TRUE.
   - number of remaining bytes from 'rptr' to the end of the owning section's
     raw data: 'p_n_raw_rem'. Always set to a positive value if the func returns
     TRUE.
   - corresponding rva address: 'p_rva'. May be set to zero if that part of file
     is not loaded to memory.
   Returns TRUE if an owning section's of 'rva' has been found. FALSE otherwise.
 */
BOOL get_rptr_info(const IMAGE_SECTION_HEADER *p_sectab, DWORD n_sects,
    DWORD rptr, DWORD *p_sect_i, DWORD *p_n_raw_rem, DWORD *p_rva);

/* Convert RVA address 'rva' into the raw file pointer (written under
   'p_raw_ptr'). Number of bytes from the RVA into the end of the owning
   section's raw data is returned under 'p_n_raw_rem'. Section table used for
   conversion is fetched from the handle 'p_hndl'. If the RVA address can not be
   converted FALSE is returned.
 */
inline BOOL get_raw_ptr(const dump_pe_hndl_t *p_hndl,
    DWORD rva, DWORD *p_raw_ptr, DWORD *p_n_raw_rem, DWORD *p_sect_i)
{
    return get_rva_info(p_hndl->sectab,
        p_hndl->n_sects, rva, p_sect_i, p_n_raw_rem, NULL, p_raw_ptr);
}

/* print_pe_details() input flags */
#define PRNTPE_DOS_HEADER  0x01U
#define PRNTPE_PE_HEADERS  0x02U
#define PRNTPE_DIRS        0x04U
#define PRNTPE_SECTS       0x08U

/* Print PE file details */
void print_pe_details(ULONG64 mod_base, DWORD flags);

/* Initialize print PE dir details handle; return TRUE on success */
BOOL init_prnt_dir_hndl(prnt_dir_hndl_t *p_hndl,
    ULONG64 mod_base, UINT dir_id, const rng_spec_t *p_rng);

/* Print PE file's load config details */
void print_lconf(ULONG64 mod_base, const rng_spec_t *p_rng);

/* Print PE file's TLS details */
void print_tls(ULONG64 mod_base, const rng_spec_t *p_rng);

/* Print PE file's debug details */
void print_debug(ULONG64 mod_base, const rng_spec_t *p_rng);

/* Print PE file's base relocs details */
void print_reloc(ULONG64 mod_base, const rng_spec_t *p_rng);

/* The main routine dumping PE structs from memory to file. 'dmp_sect' specifies
   additional section(s) to extract: 0 - no extract, -1: all sects, other value:
   number of sect.
 */
BOOL pe_dump(ULONG64 mod_base, DWORD dmp_sect);

#define PROPSC_READ_CONF    0x01U

/* Print proposal of sections names and characteristics */
void suggest_sects_chrt_name(ULONG64 mod_base, DWORD flags);

#endif /* __DUMPEXT_PEBASE_H__ */
