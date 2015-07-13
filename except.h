/*
   Copyright (c) 2015 Piotr Stolarz
   dumpext: PE files fix, dump & analysis WinDbg extension

   Distributed under the GNU General Public License (the License)
   see accompanying file LICENSE for details.

   This software is distributed WITHOUT ANY WARRANTY; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the License for more information.
 */

#ifndef __DUMPEXT_EXCEPT_H__
#define __DUMPEXT_EXCEPT_H__

/* verbosity level */
#define PRNTEXCPT_INFO_NORMAL       0U
#define PRNTEXCPT_INFO_DETAILED     1U
#define PRNTEXCPT_INFO_VERBOSE      2U

/* Print PE exception table details */
void print_except(ULONG64 mod_base, const rng_spec_t *p_rng, DWORD info_details);

#endif /* __DUMPEXT_EXCEPT_H__ */
