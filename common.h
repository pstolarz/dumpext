/*
   Copyright (c) 2015 Piotr Stolarz
   dumpext: PE files fix, dump & analysis WinDbg extension

   Distributed under the GNU General Public License (the License)
   see accompanying file LICENSE for details.

   This software is distributed WITHOUT ANY WARRANTY; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the License for more information.
 */

#ifndef __DUMPEXT_COMMON_H__
#define __DUMPEXT_COMMON_H__

#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#include <dbgeng.h>
#include <stdint.h>
#include "endian.h"
#include "rdflags.h"

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE !FALSE
#endif

#ifndef NULL
#define NULL 0
#endif

#define ARRAY_SZ(a) (sizeof((a))/sizeof((a)[0]))

#define RNDUP(x, d) ((d)*(((x)+((d)-1))/(d)))
/* special cases */
#define RNDUP_W(x)  ((((x)+1)>>1)<<1)
#define RNDUP_DW(x) ((((x)+3)>>2)<<2)

/* TLS and dbg client related funcs */
void set_tls_i(DWORD tls_i);
DWORD get_tls_i(void);

/* Get/set debug client object */
void set_client(PDEBUG_CLIENT4 Client);
PDEBUG_CLIENT4 get_client(void);

#define DBGPRNT_OUTCTL_FLAGS DEBUG_OUTCTL_ALL_CLIENTS
#define DBGPRNT_OUTPUT_FLAGS DEBUG_OUTPUT_NORMAL

/* dbg printf related functions */
void dbgprintf(const char *format, ...);
void dbg_dbgprintf(const char *format, ...);
void info_dbgprintf(const char *format, ...);
void warn_dbgprintf(const char *format, ...);
void err_dbgprintf(const char *format, ...);

/* Memory access funcs */
ULONG read_memory(ULONG64 addr, PVOID p_buf, ULONG buf_sz, PULONG p_cb);
ULONG write_memory(ULONG64 addr, PVOID p_buf, ULONG buf_sz, PULONG p_cb);

/* Expression evaluation */
BOOL get_expression(PCSTR pc_expr, ULONG64 *p_val, PCSTR *ppc_rem);

/* Copy target's string 'targ_in_addr' into local buf 'pc_out_buf' ('out_buf_len'
   long, which should be a divisible by 4). The func checks if the copied string
   fits into the buffer and returns FALSE if the buffer is too small for the
   string. 'end_chr' specifies end-of-string char (by default 0). Copied string
   is NULL terminated w/o the end-of-string char.
 */
BOOL string_cpy_lt(
    char *pc_out_buf, ULONG64 targ_in_addr, size_t out_buf_len, int end_chr=0);

/* Compare local string 'pc_str1' with target's string 'str2_addr' */
int string_cmp_lt(const char *pc_str1, ULONG64 str2_addr);

/* Reverse memchr(): look for a byte with a value other than 'val' */
void *rmemchr(const void *ptr, int val, size_t num);

/* Extract file name from full path */
char *name_from_path(const char *pc_path);

/* Retrieve file name (w/o extension) from full file name and write to 'pc_buf' */
void get_file_name(const char *pc_file_name, char *pc_buf, size_t buf_len);

typedef struct _rng_spec_t
{
    BOOL is_sect;               /* TRUE: section range */
    union {
        DWORD sect;             /* 1-based sect index, -1: all sections */

        struct {
            BOOL is_rva;        /* TRUE: rva instead of real addr */
            union {
                DWORD rva;      /* rva address */
                ULONG64 addr;   /* real address */
            };

            DWORD len;          /* range length, -1: no length specified */
        } rng;
    };
} rng_spec_t;

typedef enum _rngspc_rc_t
{
    rngspc_ok=0,
    rngspc_not_prov,            /* range spec. not provided */
    rngspc_err                  /* specification error */
} rngspc_rc_t;

/* Read range specification from command flags whose description is indicated
   by 'p_fdsc' and write the result under 'p_rng'. The func reads all recognized
   flags and modifies *p_fdsc accordingly.
 */
rngspc_rc_t get_range_spec(PCSTR *p_args, flag_desc_t *p_fdsc, rng_spec_t *p_rng);

typedef enum _cpy_ret_t
{
    cpy_ok = 0,     /* success */
    cpy_src_err,    /* source access error */
    cpy_dst_err     /* destination access error */
} cpy_ret_t;

/* Copy memory starting from address 'mem_addr' with 'sz' size into file 'f'
   (from its current position).
 */
cpy_ret_t mem2file(FILE *f, ULONG64 mem_addr, ULONG sz);

/* Copy a file (from its current position) into memory (at 'mem_addr' address)
   with size 'sz'. If 'sz' is zero copy up to the end of the file.
 */
cpy_ret_t file2mem(ULONG64 mem_addr, FILE *f, size_t sz);

/* Copy 'sz' bytes of 'f_in' (from its current position) into the file 'f_out'
   (from its current position). If 'sz' is zero copy up to the end of 'f_in' file.
 */
cpy_ret_t file2file(FILE *f_out, FILE *f_in, size_t sz);

#endif /* __DUMPEXT_COMMON_H__ */
