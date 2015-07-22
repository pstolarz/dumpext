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
#include <stdarg.h>

/*
    TLS and dbg client related funcs
 */
static DWORD tls_i=TLS_OUT_OF_INDEXES;

void set_tls_i(DWORD tls_i) {
    ::tls_i=tls_i;
}

DWORD get_tls_i(void) {
    return tls_i;
}

void set_client(PDEBUG_CLIENT4 Client) {
    if (tls_i!=TLS_OUT_OF_INDEXES) TlsSetValue(tls_i, Client);
}

PDEBUG_CLIENT4 get_client(void) {
    return (PDEBUG_CLIENT4)
        (tls_i!=TLS_OUT_OF_INDEXES ? TlsGetValue(tls_i) : NULL);
}

static void vdbgprintf(ULONG ctrl,
    ULONG mask, const char *pc_pref, const char *format, va_list args)
{
    IDebugControl *DebugControl=NULL;

    PDEBUG_CLIENT4 Client;
    if (!(Client=get_client())) goto finish;

    if (Client->QueryInterface(
        __uuidof(IDebugControl), (void **)&DebugControl)!=S_OK) goto finish;

    if (pc_pref) DebugControl->ControlledOutput(ctrl, mask, "%s: ", pc_pref);
    DebugControl->ControlledOutputVaList(ctrl, mask, format, args);

finish:
    if (DebugControl) DebugControl->Release();
    return;
}

#define DBGPRNT_METHOD(name, pref)                    \
    void name(const char *format, ...) {              \
        va_list args;                                 \
        va_start(args, format);                       \
        vdbgprintf(DBGPRNT_OUTCTL_FLAGS,              \
            DBGPRNT_OUTPUT_FLAGS, pref, format, args);\
        va_end(args);                                 \
    }

DBGPRNT_METHOD(dbgprintf, NULL)
DBGPRNT_METHOD(dbg_dbgprintf, "DBG")
DBGPRNT_METHOD(info_dbgprintf, "INFO")
DBGPRNT_METHOD(warn_dbgprintf, "WARN")
DBGPRNT_METHOD(err_dbgprintf, "ERR")

/*
    Memory access functions
 */
#define MEMACCESS_METHOD(name, func)                                         \
    ULONG name(ULONG64 addr, PVOID p_buf, ULONG buf_sz, PULONG p_cb)         \
    {                                                                        \
        ULONG ret=FALSE;                                                     \
        IDebugDataSpaces *DebugDataSpaces=NULL;                              \
                                                                             \
        PDEBUG_CLIENT4 Client;                                               \
        if (Client=get_client()) {                                           \
            if (Client->QueryInterface(__uuidof(IDebugDataSpaces),           \
                (void **)&DebugDataSpaces)==S_OK) {                          \
                ret=(DebugDataSpaces->func(addr, p_buf, buf_sz, p_cb)==S_OK);\
            }                                                                \
        }                                                                    \
                                                                             \
        if (DebugDataSpaces) DebugDataSpaces->Release();                     \
        return ret;                                                          \
    }

/* WdbgExts ReadMemory(), WriteMemory() analogous */
MEMACCESS_METHOD(read_memory, ReadVirtual)
MEMACCESS_METHOD(write_memory, WriteVirtual)

/* WdbgExts GetExpressionEx() analogous */
BOOL get_expression(PCSTR pc_expr, ULONG64 *p_val, PCSTR *ppc_rem)
{
    BOOL ret=FALSE;
    IDebugControl *DebugControl=NULL;

    PDEBUG_CLIENT4 Client;
    if (!(Client=get_client())) goto finish;

    if ((Client->QueryInterface(
        __uuidof(IDebugControl), (void **)&DebugControl))!=S_OK) goto finish;

    ULONG rem_i;
    DEBUG_VALUE val;
    if (DebugControl->Evaluate(
        pc_expr, DEBUG_VALUE_INT64, &val, &rem_i)!=S_OK) goto finish;

    if (ppc_rem) {
        for (pc_expr+=rem_i; isspace(*pc_expr); pc_expr++);
        *ppc_rem = pc_expr;
    }
    *p_val = (ULONG64)val.I64;

    ret=TRUE;
finish:
    if (DebugControl) DebugControl->Release();
    return ret;
}

/* exported; see header for details */
BOOL string_cpy_lt(
    char *pc_out_buf, ULONG64 targ_in_addr, size_t out_buf_len, int end_chr)
{
    BOOL ret=FALSE;
    UINT32 dw;
    char *pc_dw = (char*)&dw;

    for (size_t i=0; i<out_buf_len; targ_in_addr+=sizeof(dw), i+=sizeof(dw))
    {
        ULONG cb;
        if (!(read_memory(
            targ_in_addr, &dw, sizeof(dw), &cb) && cb==sizeof(dw))) goto err;

        for (size_t j=0; j<sizeof(dw); j++)
            if ((pc_out_buf[i+j]=pc_dw[j])==(char)end_chr) {
                pc_out_buf[i+j]=0;
                goto no_err;
            }
    }

    /* string to long (end-of-string char absent) */
    goto err;

no_err:
    ret=TRUE;
err:
    return ret;
}

/* exported; see header for details */
int string_cmp_lt(const char *pc_str1, ULONG64 str2_addr)
{
    int ret=-1;
    UINT32 dw;
    char *pc_dw = (char*)&dw;

    for (size_t i=0;; str2_addr+=sizeof(dw), i+=sizeof(dw))
    {
        ULONG cb;
        if (!(read_memory(
            str2_addr, &dw, sizeof(dw), &cb) && cb==sizeof(dw))) break;

        for (size_t j=0; j<sizeof(dw); j++) {
            if (ret=pc_str1[i+j]-pc_dw[j]) goto finish;
            if (!pc_dw[j]) goto finish;
        }
    }

finish:
    return ret;
}

/* exported; see header for details */
void *rmemchr(const void *ptr, int val, size_t num)
{
    void *ret=NULL;

    for (size_t i=0; i<num; i++)
        if (((char*)ptr)[i]!=val) { ret=(void*)&(((char*)ptr)[i]); break; }

    return ret;
}

/* exported; see header for details */
char *name_from_path(const char *pc_path)
{
    const char *pc_name = pc_path;

    const char *sl = strrchr(pc_path, '/');
    const char *bsl = strrchr(pc_path, '\\');
    const char *col = strrchr(pc_path, ':');

    if (bsl) pc_name=bsl+1;
    else
    if (sl) pc_name=sl+1;
    else
    if (col) pc_name=col+1;

    return (char*)pc_name;
}

/* exported; see header for details */
void get_file_name(const char *pc_file_name, char *pc_buf, size_t buf_len)
{
    pc_file_name = name_from_path(pc_file_name);

    const char *dot = strrchr(pc_file_name, '.');
    if (dot) {
        size_t i;

        for (i=0; i<buf_len-1 && pc_file_name+i<dot; i++)
            pc_buf[i]=pc_file_name[i];

        pc_buf[i]=0;
    } else {
        strncpy(pc_buf, pc_file_name, buf_len);
        pc_buf[buf_len-1]=0;
    }
}

/* exported; see header for details */
rngspc_rc_t get_range_spec(PCSTR *p_args, flag_desc_t *p_fdsc, rng_spec_t *p_rng)
{
    rngspc_rc_t ret=rngspc_ok;
 
    size_t rd_sz = read_flags(*p_args, p_fdsc);
    *p_args += rd_sz;

    BOOL b_rva=FALSE, b_addr=FALSE, b_len=FALSE, b_sect=FALSE;
    for (UINT i=0; ret==rngspc_ok && i<p_fdsc[i].c_flag; i++)
    {
        if (!p_fdsc[i].is_pres) continue;

        ULONG64 arg;
        BOOL arg_err=TRUE;
        size_t arg_len = p_fdsc[i].arg_len;
        char *pc_arg = p_fdsc[i].pc_arg;

        /* read argument */
        if (arg_len > 0) {
            char c = pc_arg[arg_len];
            pc_arg[arg_len] = 0;
            if (get_expression(pc_arg, &arg, NULL)) arg_err=FALSE;
            pc_arg[arg_len] = c;
        }

        /* ... and save result into the out struct */
        switch (p_fdsc[i].c_flag)
        {
        case 'r':
            b_rva=TRUE;
            p_rng->is_sect=FALSE;

            if (!arg_err && arg<=(DWORD)-1) {
                p_rng->rng.is_rva=TRUE;
                p_rng->rng.rva=(DWORD)arg;
            } else
                arg_err=TRUE;
            break;

        case 'a':
            b_addr=TRUE;
            p_rng->is_sect=FALSE;

            if (!arg_err) {
                p_rng->rng.is_rva=FALSE;
                p_rng->rng.addr=arg;
            }
            break;

        case 'l':
            b_len=TRUE;
            p_rng->is_sect=FALSE;

            if (!arg_err && arg<(DWORD)-1) {
                p_rng->rng.len=(DWORD)arg;
            } else
                arg_err=TRUE;
            break;

        case 's':
            b_sect=TRUE;
            p_rng->is_sect=TRUE;

            if (arg_len==1 && pc_arg[0]=='*') {
                arg_err=FALSE;
                p_rng->sect=(DWORD)-1;
            } else
            if (!arg_err && arg>=1 && arg<(DWORD)-1) {
                p_rng->sect=(DWORD)arg;
            } else
                arg_err=TRUE;
            break;

        default:
            continue;
        }

        if (arg_err) { ret=rngspc_err; goto finish; }
    }

    /* check correctness of all provided args */
    if (b_sect || b_rva || b_addr || b_len)
    {
        if (b_sect && (b_rva || b_addr || b_len)) ret=rngspc_err;
        else
        if (!b_sect) {
            if ((b_rva && b_addr) || (!b_rva && !b_addr)) ret=rngspc_err;
            else
            if (!b_len) p_rng->rng.len = (DWORD)-1;
        }
    } else ret=rngspc_not_prov;

finish:
    return ret;
}

/* exported; see header for details */
cpy_ret_t mem2file(FILE *f, ULONG64 mem_addr, ULONG sz)
{
    char read_buf[0x400];
    cpy_ret_t ret = cpy_ok;

    for (ULONG off=0; sz;)
    {
        ULONG cb;
        ULONG read_sz = (sz<=sizeof(read_buf) ? sz : sizeof(read_buf));

        if (!(read_memory(mem_addr+off, read_buf, read_sz, &cb) && cb==read_sz))
            { ret=cpy_src_err; goto finish; }
        if (fwrite(read_buf, 1, read_sz, f)!=read_sz)
            { ret=cpy_dst_err; goto finish; }

        sz -= read_sz;
        off += read_sz;
    }

finish:
    return ret;
}

/* exported; see header for details */
cpy_ret_t file2mem(ULONG64 mem_addr, FILE *f, size_t sz)
{
    size_t off=0;
    char read_buf[0x400];
    BOOL b_loopcnt=TRUE;
    cpy_ret_t ret = cpy_ok;

    for (size_t to_proc=sz; b_loopcnt && (!sz || to_proc);)
    {
        ULONG cb;
        size_t read_sz =
            (!sz || (to_proc>sizeof(read_buf)) ? sizeof(read_buf) : to_proc);

        if ((cb=fread(read_buf, 1, read_sz, f))!=read_sz) {
            if (sz) { ret=cpy_src_err; break; }
            else { read_sz=cb; b_loopcnt=FALSE; }
        }

        if (!(write_memory(mem_addr+off, read_buf, read_sz, &cb) && cb==read_sz))
            { ret=cpy_dst_err; goto finish; }

        to_proc-=read_sz;
        off+=read_sz;
    }

finish:
    return ret;
}

/* exported; see header for details */
cpy_ret_t file2file(FILE *f_out, FILE *f_in, size_t sz)
{
    char read_buf[0x400];
    BOOL b_loopcnt=TRUE;
    cpy_ret_t ret = cpy_ok;

    for (size_t to_proc=sz; b_loopcnt && (!sz || to_proc);)
    {
        size_t cb;
        size_t read_sz =
            (!sz || (to_proc>sizeof(read_buf)) ? sizeof(read_buf) : to_proc);

        if ((cb=fread(read_buf, 1, read_sz, f_in))!=read_sz) {
            if (sz) { ret=cpy_src_err; break; }
            else { read_sz=cb; b_loopcnt=FALSE; }
        }

        if (fwrite(read_buf, 1, read_sz, f_out)!=read_sz)
            { ret=cpy_dst_err; break; }

        to_proc-=read_sz;
    }

    return ret;
}
