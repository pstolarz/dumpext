/*
   Copyright (c) 2015 Piotr Stolarz
   dumpext: PE files fix, dump & analysis WinDbg extension

   Distributed under the GNU General Public License (the License)
   see accompanying file LICENSE for details.

   This software is distributed WITHOUT ANY WARRANTY; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the License for more information.
 */

#ifndef __RDFLAGS_H__
#define __RDFLAGS_H__

typedef struct _flag_desc_t
{
    /* read_flags() input fields */
    char c_flag;        /* flag's char */
    int allow_arg;      /* if !=0 the flag may be provided with an arg */

    /* read_flags() output fields */
    struct {
        unsigned int is_pres:  1;   /* flag has been found */
        unsigned int has_dups: 1;   /* duplicated flags occurred */
        unsigned int has_esc:  1;   /* " or ' chars escaped inside the 'pc_arg'
                                       string */
    };
    size_t arg_len;     /* flag's argument length */
    char *pc_arg;       /* points to flag's argument (if arg_len>0) */
} flag_desc_t;

/* Read flags from 'pc_in' and write under 'p_dsc' table (with length 'n_fdsc').
   Return number of read chars from the input.

   NOTES:
   1. Unknown flags are ignored.
   2. If a flag with an arg allowed, occurs more than once, the last occurrence
      (and its arg) is taken into account. Duplicated flags existence is indicated
      by 'has_dups' flag.
   3. The " and ' chars may be escaped inside arg enclosed by them, but the
      func doesn't replace them in the 'pc_in' string. The 'has_esc' flag is set
      to indicate this case.
 */
size_t read_flags(const char *pc_in, flag_desc_t *p_fdsc, size_t n_fdsc);

#endif /* __RDFLAGS_H__ */
