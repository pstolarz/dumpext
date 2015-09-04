/*
   Copyright (c) 2015 Piotr Stolarz
   dumpext: PE files fix, dump & analysis WinDbg extension

   Distributed under the GNU General Public License (the License)
   see accompanying file LICENSE for details.

   This software is distributed WITHOUT ANY WARRANTY; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the License for more information.
 */

#ifndef __DUMPEXT_RESRC_H__
#define __DUMPEXT_RESRC_H__

#define PRNTRSRC_CAPAC      0x01U
#define PRNTRSRC_CAPAC_ONLY 0x02U

/* Print resources details */
void print_rsrc(ULONG64 mod_base, const rng_spec_t *p_rng, DWORD flags);

/* Fix resources in the dumped file. The func modifies resource directory info
   contained in the NT header inside the dump_pe handle (pointed by 'p_hndl').
 */
BOOL fix_rsrc(const dump_pe_hndl_t *p_hndl);

#endif /* __DUMPEXT_RESRC_H__ */
