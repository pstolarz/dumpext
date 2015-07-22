/*
   Copyright (c) 2015 Piotr Stolarz
   dumpext: PE files fix, dump & analysis WinDbg extension

   Distributed under the GNU General Public License (the License)
   see accompanying file LICENSE for details.

   This software is distributed WITHOUT ANY WARRANTY; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the License for more information.
 */

#include <common.h>

/* exported; see header for details */
size_t read_flags(const char *pc_in, flag_desc_t *p_fdsc)
{
    int state=0;
    char arg_delim;
    size_t i, j, arg_i;

    /* clear output fields */
    for (j=0; p_fdsc[j].c_flag; j++) {
        p_fdsc[j].is_pres=0;
        p_fdsc[j].has_dups=0;
        p_fdsc[j].has_esc=0;
        p_fdsc[j].arg_len=0;
        p_fdsc[j].pc_arg=NULL;
    }

    for (i=0; pc_in[i] && state>=0; i++)
    {
        switch (state)
        {
        /* read until flag prefix: '-' */
        case 0:
            if (!isspace(pc_in[i])) {
                if (pc_in[i]=='-') state=1;
                else {
                    /* no more flags; finish parsing */
                    i--; state=-1;
                }
            }
            break;

        /* recognize flag marker */
        case 1:
            if (isspace(pc_in[i])) {
                /* no flag provided; prepare for reading the next flag */
                state=0;
            } else
            if (pc_in[i]=='"' || pc_in[i]=='\'') {
                /* arg to unknown flag; finish parsing */
                i--; state=-1;
            } else
            if (pc_in[i]=='-') {
                /* ignore sequences of '-' (no long arg supported) */
            } else {
                for (j=0; p_fdsc[j].c_flag; j++)
                {
                    if (p_fdsc[j].c_flag==pc_in[i]) {
                        if (p_fdsc[j].is_pres) {
                            p_fdsc[j].has_dups=1;
                            p_fdsc[j].has_esc=0;
                            p_fdsc[j].arg_len=0;
                            p_fdsc[j].pc_arg=NULL;
                        } else {
                            p_fdsc[j].is_pres=1;
                        }
                        break;
                    }
                }
                if (p_fdsc[j].c_flag) {
                    if (p_fdsc[j].allow_arg) {
                        arg_i=j;
                        state=2;
                    }
                } else {
                    /* unknown flag, ignore it and read the next one */
                }
            }
            break;

        /* recognize flag arg delimiter
           input:
           arg_i: index of flag desc
         */
        case 2:
            /* read until start of arg */
            if (!isspace(pc_in[i])) {
                if (pc_in[i]=='-') {
                    /* no arg provided */
                    state=1; continue;
                } else
                if (pc_in[i]=='"') {
                    arg_delim='"';
                    p_fdsc[arg_i].pc_arg = (char*)&pc_in[i+1];
                } else
                if (pc_in[i]=='\'') {
                    arg_delim='\'';
                    p_fdsc[arg_i].pc_arg = (char*)&pc_in[i+1];
                } else {
                    arg_delim=0;
                    p_fdsc[arg_i].arg_len++;
                    p_fdsc[arg_i].pc_arg = (char*)&pc_in[i];
                }
                state=3;
            }
            break;

        /* read flag arg
           input:
           arg_delim; 0:white space
           arg_i: index of flag desc */
        case 3:
            if (!arg_delim) {
                if (isspace(pc_in[i])) state=0;
                else
                if (pc_in[i]=='-') state=1;
                else
                p_fdsc[arg_i].arg_len++;
            } else {
                if (arg_delim==pc_in[i]) state=1;
                else {
                    if (pc_in[i]=='\\') state=4;
                    p_fdsc[arg_i].arg_len++;
                }
            }
            break;

        /* escaped char in apostrophed flag arg */
        case 4:
            if (pc_in[i]=='"' || pc_in[i]=='\'') {
                p_fdsc[arg_i].has_esc=1;
            }
            p_fdsc[arg_i].arg_len++;
            state=3;
            break;
        }
    }
    return i;
}
