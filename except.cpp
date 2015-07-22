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
#include "except.h"

/* x64 specific info
 */

#include "pshpack1.h"

/* unwind operation codes (x64) */
typedef enum _UNWIND_OP_CODES_X64
{
    X64_UWOP_PUSH_NONVOL = 0,
    X64_UWOP_ALLOC_LARGE,
    X64_UWOP_ALLOC_SMALL,
    X64_UWOP_SET_FPREG,
    X64_UWOP_SAVE_NONVOL,
    X64_UWOP_SAVE_NONVOL_FAR,
    X64_UWOP_SPARE_CODE1,
    X64_UWOP_SPARE_CODE2,
    X64_UWOP_SAVE_XMM128,
    X64_UWOP_SAVE_XMM128_FAR,
    X64_UWOP_PUSH_MACHFRAME
} UNWIND_OP_CODES_X64;

typedef union _UNWIND_CODE_X64
{
    struct {
        UCHAR CodeOffset;
        UCHAR OpInfo_UnwindOp;      /* 0..3:UnwindOp, 4..7:OpInfo */
    };
    USHORT FrameOffset;
} UNWIND_CODE_X64, *PUNWIND_CODE_X64;

/* unwind information flags (x64) */
#define X64_UNW_FLAG_NHANDLER   0
#define X64_UNW_FLAG_EHANDLER   1
#define X64_UNW_FLAG_UHANDLER   2
#define X64_UNW_FLAG_CHAININFO  4

typedef struct _UNWIND_INFO_X64
{
    UCHAR Flags_Version;            /* 3..7:Flags, 0..2:Version */
    UCHAR SizeOfProlog;
    UCHAR CountOfCodes;
    UCHAR FrameOffset_FrameRegister;/* 4..7:FrameOffset, 0..3:FrameRegister */
/*
    // # of elements as provided in CountOfCodes
    UNWIND_CODE_X64 UnwindCode[];

    // The unwind codes are followed by an optional DWORD aligned field that
    // contains the exception handler address or a function table entry if
    // chained unwind information is specified. If an exception handler address
    // is specified, then it is followed by the language specified exception
    // handler data.
    union
    {
        struct {
            DWORD ExceptionHandler;
            DWORD ExceptionData[];
        };
        RUNTIME_FUNCTION_X64 FunctionEntry;
    };
*/

} UNWIND_INFO_X64, *PUNWIND_INFO_X64;

typedef struct _RUNTIME_FUNCTION_X64
{
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
} RUNTIME_FUNCTION_X64, *PRUNTIME_FUNCTION_X64;

#include "poppack.h"

/* IA64 specific info
 */
typedef RUNTIME_FUNCTION_X64 RUNTIME_FUNCTION_IA64;

/* Print x64 unwind flags */
static void print_x64_uwind_flags(UINT flags)
{
    if (flags!=X64_UNW_FLAG_NHANDLER) {
        UINT n_flags=0;
        if (flags&X64_UNW_FLAG_EHANDLER) {
            dbgprintf("excpt_hndlr"); n_flags++;
        }
        if (flags&X64_UNW_FLAG_UHANDLER) {
            dbgprintf("%suwind_hndlr", (n_flags ? "|" : "")); n_flags++;
        }
        if (flags&X64_UNW_FLAG_CHAININFO) {
            dbgprintf("%schained_hndlr", (n_flags ? "|" : "")); n_flags++;
        }
    } else {
        dbgprintf("no_hndlr");
    }
}

/* Get x64 register name */
static LPCSTR get_x64_gpr_name(UINT reg)
{
    static LPCSTR reg_names[] =
        {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
         "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};

    return reg_names[reg&0x0f];
}

/* Print unwind codes info */
static void print_ucodes(const UNWIND_CODE_X64 *p_ucodes, UINT n_ucodes)
{
    UINT slots=0;
    for (UINT i=0; i<n_ucodes; i++, slots--)
    {
        if (!slots)
        {
            char info_buf[64];
            LPCSTR oper_name = "???";
            LPCSTR info_name = NULL;
            UINT oper_code = p_ucodes[i].OpInfo_UnwindOp&0x0f;
            UINT oper_info = (p_ucodes[i].OpInfo_UnwindOp>>4)&0x0f;

            slots = 1;
            switch (oper_code)
            {
            case X64_UWOP_PUSH_NONVOL:
                oper_name="push_non_vol";
                info_name=get_x64_gpr_name(oper_info);
                break;
            case X64_UWOP_ALLOC_LARGE:
                oper_name = "alloc_large";
                if (!oper_info) slots=2;
                else
                if (oper_info==1) slots=3;
                break;
            case X64_UWOP_ALLOC_SMALL:
                oper_name = "alloc_small";
                sprintf(info_buf, "alloc_0x%02X", 8*(oper_info+1));
                info_name=info_buf;
                break;
            case X64_UWOP_SET_FPREG:
                oper_name = "set_frmptr_reg";
                break;
            case X64_UWOP_SAVE_NONVOL:
                slots=2;
                oper_name = "save_non_vol";
                info_name=get_x64_gpr_name(oper_info);
                break;
            case X64_UWOP_SAVE_NONVOL_FAR:
                slots=3;
                oper_name = "save_non_vol_far";
                info_name=get_x64_gpr_name(oper_info);
                break;
            case X64_UWOP_SPARE_CODE1:
                oper_name = "spare_code1";
                break;
            case X64_UWOP_SPARE_CODE2:
                oper_name = "spare_code2";
                break;
            case X64_UWOP_SAVE_XMM128:
                slots=2;
                oper_name = "save_xmm128";
                sprintf(info_buf, "xmm%d", oper_info);
                info_name=info_buf;
                break;
            case X64_UWOP_SAVE_XMM128_FAR:
                slots=3;
                oper_name = "save_xmm128_far";
                sprintf(info_buf, "xmm%d", oper_info);
                info_name=info_buf;
                break;
            case X64_UWOP_PUSH_MACHFRAME:
                oper_name = "push_mach_frm";
                break;
            default:
                oper_name = "???";
                break;
            }

            dbgprintf(
                "    0x%02X:0x%02X ;   prolog off:%d, oper code:%s(%d), oper info:",
                p_ucodes[i].CodeOffset, p_ucodes[i].OpInfo_UnwindOp,
                p_ucodes[i].CodeOffset, oper_name, oper_code);
            if (info_name) dbgprintf("%s(%d)\n", info_name, oper_info);
            else dbgprintf("%d\n", oper_info);
        } else {
            dbgprintf(
                "    0x%02X:0x%02X ;   param slot\n",
                p_ucodes[i].CodeOffset, p_ucodes[i].OpInfo_UnwindOp);
        }
    }
}

/* x64 exception specification details */
static void print_x64_except(
    const prnt_dir_hndl_t *p_hndl, const rng_spec_t *p_rng, DWORD info_details)
{
    DWORD off=0;
    RUNTIME_FUNCTION_X64 fun_ent;
    DWORD len_cnstr = (p_rng ? p_rng->rng.len : p_hndl->dir_sz);

    info_dbgprintf("x64 exception table:\n");

    for (;; off+=sizeof(fun_ent),
        len_cnstr-=(len_cnstr!=(DWORD)-1 ? sizeof(fun_ent) : 0))
    {
        if (len_cnstr!=(DWORD)-1 && len_cnstr<sizeof(fun_ent)) break;

        ULONG cb;
        if (!(read_memory(p_hndl->dir_addr+off, &fun_ent, sizeof(fun_ent), &cb)
            && cb==sizeof(fun_ent))) break;

        /* break on if some of required BeginAddress/UnwindData fields
           are absent */
        if (!fun_ent.BeginAddress || !fun_ent.UnwindData) break;

        UNWIND_INFO_X64 uwind;
        ULONG64 uwind_addr =
            RVA2ADDR(get_32uint_le(&fun_ent.UnwindData), p_hndl->mod_base);

        dbgprintf("0x%p[0x%08X] Func. begin/end/unwind info addr: "
            "0x%p[0x%08X] 0x%p[0x%08X] 0x%p[0x%08X]\n",
            p_hndl->dir_addr+off,
            ADDR2RVA(p_hndl->dir_addr+off, p_hndl->mod_base),
            RVA2ADDR(get_32uint_le(&fun_ent.BeginAddress), p_hndl->mod_base),
            get_32uint_le(&fun_ent.BeginAddress),
            RVA2ADDR(get_32uint_le(&fun_ent.EndAddress), p_hndl->mod_base),
            get_32uint_le(&fun_ent.EndAddress),
            uwind_addr,
            get_32uint_le(&fun_ent.UnwindData));

        if (info_details<=PRNTEXCPT_INFO_NORMAL) continue;

        if (!(read_memory(uwind_addr,
            &uwind, sizeof(uwind), &cb) && cb==sizeof(uwind))) break;

        UINT flags = (uwind.Flags_Version>>3)&0x1f;
        UINT frame_reg = uwind.FrameOffset_FrameRegister&0x0f;
        UINT n_ucodes = uwind.CountOfCodes;

        dbgprintf(" Unwind info:\n");
        dbgprintf("  Flags/Version:       0x%02X   ; flags:",
            uwind.Flags_Version);
        print_x64_uwind_flags(flags);
        dbgprintf("(%d), ver:%d\n", flags, uwind.Flags_Version&0x07);

        dbgprintf("  Prolog size:         0x%02X\n", uwind.SizeOfProlog);
        dbgprintf("  Num. of unwind codes:0x%02X\n", n_ucodes);

        dbgprintf("  Frame offset/reg:    0x%02X",
            uwind.FrameOffset_FrameRegister);

        if (frame_reg) {
            dbgprintf("   ; off:%d, reg:%s(%d)\n",
            (uwind.FrameOffset_FrameRegister>>4)&0x0f,
            get_x64_gpr_name(frame_reg), frame_reg);
        } else
            dbgprintf("\n");

        ULONG uwind_cds_sz =
            sizeof(UNWIND_CODE_X64)*(n_ucodes+(n_ucodes&1 ? 1 : 0));
        ULONG64 uwind_cds_addr = uwind_addr+sizeof(UNWIND_INFO_X64);
        ULONG uwind_rem_sz =
            uwind_cds_sz+(flags&X64_UNW_FLAG_CHAININFO ?
            sizeof(RUNTIME_FUNCTION_X64) :
            (flags&X64_UNW_FLAG_EHANDLER ? sizeof(DWORD) : 0));

        UINT8 uwind_dta[0x210];
        if (!(read_memory(uwind_cds_addr,
            uwind_dta, uwind_rem_sz, &cb) && cb==uwind_rem_sz)) break;

        if (n_ucodes>0) dbgprintf("  Unwind located at mem. range 0x%p..0x%p\n",
            uwind_cds_addr, uwind_cds_addr+sizeof(UNWIND_CODE_X64)*n_ucodes-1);

        if (info_details==PRNTEXCPT_INFO_VERBOSE) {
            print_ucodes((UNWIND_CODE_X64*)&uwind_dta[0], n_ucodes);
        }

        if (flags&X64_UNW_FLAG_EHANDLER)
        {
            DWORD exp_hndlr_rva = get_32uint_le(&uwind_dta[uwind_cds_sz]);
            ULONG64 exp_hndlr_addr = RVA2ADDR(exp_hndlr_rva, p_hndl->mod_base);

            dbgprintf("  Exception handler:   0x%p[0x%08X]\n",
                exp_hndlr_addr, exp_hndlr_rva);
            dbgprintf("  Exception data at:   0x%p\n",
                exp_hndlr_addr+sizeof(DWORD));
        } else
        if (flags&X64_UNW_FLAG_CHAININFO) {
            RUNTIME_FUNCTION_X64 *p_rf =
                (RUNTIME_FUNCTION_X64*)&uwind_dta[uwind_cds_sz];

            dbgprintf("  Func. beg/end/unwnd: "
                "0x%p[0x%08X] 0x%p[0x%08X] 0x%p[0x%08X]\n",
                RVA2ADDR(get_32uint_le(&p_rf->BeginAddress), p_hndl->mod_base),
                get_32uint_le(&p_rf->BeginAddress),
                RVA2ADDR(get_32uint_le(&p_rf->EndAddress), p_hndl->mod_base),
                get_32uint_le(&p_rf->EndAddress),
                uwind_addr,
                get_32uint_le(&p_rf->UnwindData));
        }
    }
}

/* IA64 exception specification details */
static void print_ia64_except(
    const prnt_dir_hndl_t *p_hndl, const rng_spec_t *p_rng, DWORD info_details)
{
    DWORD off=0;
    RUNTIME_FUNCTION_IA64 fun_ent;
    DWORD len_cnstr = (p_rng ? p_rng->rng.len : p_hndl->dir_sz);

    info_dbgprintf("IA64 exception table:\n");

    for (;; off+=sizeof(fun_ent),
        len_cnstr-=(len_cnstr!=(DWORD)-1 ? sizeof(fun_ent) : 0))
    {
        if (len_cnstr!=(DWORD)-1 && len_cnstr<sizeof(fun_ent)) break;

        ULONG cb;
        if (!(read_memory(p_hndl->dir_addr+off, &fun_ent, sizeof(fun_ent), &cb)
            && cb==sizeof(fun_ent))) break;

        /* break on if some of required BeginAddress/UnwindData fields
           are absent */
        if (!fun_ent.BeginAddress || !fun_ent.UnwindData) break;

        dbgprintf("0x%p[0x%08X] Func. begin/end/unwind info addr: "
            "0x%p[0x%08X] 0x%p[0x%08X] 0x%p[0x%08X]\n",
            p_hndl->dir_addr+off,
            ADDR2RVA(p_hndl->dir_addr+off, p_hndl->mod_base),
            RVA2ADDR(get_32uint_le(&fun_ent.BeginAddress), p_hndl->mod_base),
            get_32uint_le(&fun_ent.BeginAddress),
            RVA2ADDR(get_32uint_le(&fun_ent.EndAddress), p_hndl->mod_base),
            get_32uint_le(&fun_ent.EndAddress),
            RVA2ADDR(get_32uint_le(&fun_ent.UnwindData), p_hndl->mod_base),
            get_32uint_le(&fun_ent.UnwindData));
    }
}

/* exported; see header for details */
void print_except(ULONG64 mod_base, const rng_spec_t *p_rng, DWORD info_details)
{
    prnt_dir_hndl_t hndl;
    if (!init_prnt_dir_hndl(
        &hndl, mod_base, IMAGE_DIRECTORY_ENTRY_EXCEPTION, p_rng)) goto finish;

    /* print header */
    if (!hndl.dir_addr || (!p_rng && !hndl.dir_sz)) {
        info_dbgprintf("No exception table in this module!\n");
        goto finish;
    } else {
        info_dbgprintf("Exception table at: 0x%p\n", hndl.dir_addr);
    }
    info_dbgprintf("RVA provided in []\n\n");

    DWORD machine = (DWORD)get_16uint_le(&get_FileHeader(&hndl.nt_hdrs).Machine);

    switch (machine)
    {
    case IMAGE_FILE_MACHINE_AMD64 :
        print_x64_except(&hndl, p_rng, info_details);
        break;
    case IMAGE_FILE_MACHINE_IA64 :
        print_ia64_except(&hndl, p_rng, info_details);
        break;
    default:
        err_dbgprintf("Unsupported PE image machine: 0x%04X\n", machine);
        break;
    }

finish:
    return;
}
