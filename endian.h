/*
   Copyright (c) 2015 Piotr Stolarz
   dumpext: PE files fix, dump & analysis WinDbg extension

   Distributed under the GNU General Public License (the License)
   see accompanying file LICENSE for details.

   This software is distributed WITHOUT ANY WARRANTY; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the License for more information.
 */

#ifndef __ENDIAN_H__
#define __ENDIAN_H__

#ifdef __BIG_ENDIAN__
/* BE platform */

/* Reads 'len' bytes long LE integer from 'in' address */
static uint64_t get_le(void *in, unsigned int len)
{
    unsigned int i;
    uint64_t ret=0;
    uint8_t *c_in = (uint8_t*)in;

    for (i=len; i>0; i--) {
        ret = ret << 8;
        ret |= c_in[i-1];
    }
    return ret;
}
# define get_16uint_le(x) (uint16_t)get_le((x), sizeof(uint16_t))
# define get_32uint_le(x) (uint32_t)get_le((x), sizeof(uint32_t))
# define get_64uint_le(x) get_le((x), sizeof(uint64_t))

/* Writes 'num' LE integer ('len' bytes long) into 'out' address */
static void set_le(void *out, uint64_t num, unsigned int len)
{
    unsigned int i;
    uint8_t *c_out = (uint8_t*)out;

    for (i=0; i<len; i++) {
        c_out[i] = num & 0xff;
        num = num >> 8;
    }
}
# define set_16uint_le(x,y) set_le((x), (y), sizeof(uint16_t))
# define set_32uint_le(x,y) set_le((x), (y), sizeof(uint32_t))
# define set_64uint_le(x,y) set_le((x), (y), sizeof(uint64_t))

# define get_16uint_be(x) *(uint16_t*)(x)
# define get_32uint_be(x) *(uint32_t*)(x)
# define get_64uint_be(x) *(uint64_t*)(x)

# define set_16uint_be(x,y) (*(uint16_t*)(x)=(uint16_t)(y))
# define set_32uint_be(x,y) (*(uint32_t*)(x)=(uint32_t)(y))
# define set_64uint_be(x,y) (*(uint64_t*)(x)=(uint64_t)(y))

#else
/* LE platform */

# define get_16uint_le(x) *(uint16_t*)(x)
# define get_32uint_le(x) *(uint32_t*)(x)
# define get_64uint_le(x) *(uint64_t*)(x)

# define set_16uint_le(x,y) (*(uint16_t*)(x)=(uint16_t)(y))
# define set_32uint_le(x,y) (*(uint32_t*)(x)=(uint32_t)(y))
# define set_64uint_le(x,y) (*(uint64_t*)(x)=(uint64_t)(y))

/* Reads 'len' bytes long BE integer from 'in' address */
static uint64_t get_be(void *in, unsigned int len)
{
    unsigned int i;
    uint64_t ret=0;
    uint8_t *c_in = (uint8_t*)in;

    for (i=0; i<len; i++) {
        ret = ret << 8;
        ret |= c_in[i];
    }
    return ret;
}
# define get_16uint_be(x) (uint16_t)get_be((x), sizeof(uint16_t))
# define get_32uint_be(x) (uint32_t)get_be((x), sizeof(uint32_t))
# define get_64uint_be(x) get_be((x), sizeof(uint64_t))

/* Writes 'num' BE integer ('len' bytes long) into 'out' address */
static void set_be(void *out, uint64_t num, unsigned int len)
{
    unsigned int i;
    uint8_t *c_out = (uint8_t*)out;

    for (i=len; i>0; i--) {
        c_out[i-1] = num & 0xff;
        num = num >> 8;
    }
}
# define set_16uint_be(x,y) set_be((x), (y), sizeof(uint16_t))
# define set_32uint_be(x,y) set_be((x), (y), sizeof(uint32_t))
# define set_64uint_be(x,y) set_be((x), (y), sizeof(uint64_t))

#endif /* __BIG_ENDIAN__ */

#endif /* __ENDIAN_H__ */
