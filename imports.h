/*
   Copyright (c) 2015 Piotr Stolarz
   dumpext: PE files fix, dump & analysis WinDbg extension

   Distributed under the GNU General Public License (the License)
   see accompanying file LICENSE for details.

   This software is distributed WITHOUT ANY WARRANTY; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the License for more information.
 */

#ifndef __DUMPEXT_IMPORTS_H__
#define __DUMPEXT_IMPORTS_H__

#include "pebase.h"

#define SCANIMPS_WRITE_CONF  0x01U

typedef enum _iscan_tpy_t
{
    iscan_iat=0,
    iscan_idt
} iscan_tpy_t;

/* Main scanning imports routine */
void scan_imports(ULONG64 mod_base,
    iscan_tpy_t iscan_tpy, const rng_spec_t *p_rng, DWORD flags);

/* Write an import patch into the dumped file. The function modifies IDT & IAT
   directories info contained in the NT header inside dump_pe handle (pointed by
   'p_hndl').
 */
BOOL patch_imports(const dump_pe_hndl_t *p_hndl);

/* Fix the IAT table for each imported module by copy corresponding ILT to the
   IAT's place. Returns TRUE on success.
 */
BOOL fix_iat(const dump_pe_hndl_t *p_hndl);

/* Bind imports of a file 'pc_pe_file'. Return TRUE on success. */
BOOL bind_imports(const char *pc_pe_file);

#define PRNTIMP_IMPSPEC     0x01U

/* Print PE file's imports */
void print_imports(ULONG64 mod_base, const rng_spec_t *p_rng, DWORD flags);

/* Print PE file's exports */
void print_exports(ULONG64 mod_base, const rng_spec_t *p_rng);

/* Print PE file's bound imports details */
void print_bound_imps(ULONG64 mod_base, const rng_spec_t *p_rng);

/* Print PE file's delayed imports details */
void print_delay_imps(ULONG64 mod_base, const rng_spec_t *p_rng);

#define SRCHIDT_NO_ORD      0x01U
#define SRCHIDT_SILENT      0x02U

/* Search a range described by spec. pointed by 'p_rng' for the IDT table witch
   matches IAT addresses as specified in the imports spec. configuration. Print
   results. If 'p_rng' is NULL the func tries to recognize best section(s) to
   search.
 */
void search_idt(ULONG64 mod_base, const rng_spec_t *p_rng, DWORD flags);

#endif /* __DUMPEXT_IMPORTS_H__ */
