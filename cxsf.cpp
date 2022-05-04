/*
    DeaDBeeF - ultimate music player for GNU/Linux systems with X11
    Copyright (C) 2009-2012 Alexey Yakovenko <waker@users.sourceforge.net>

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include <new>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <deadbeef/deadbeef.h>

#ifndef O_LARGEFILE
# define O_LARGEFILE 0
#endif

#include "Highly_Experimental/Core/psx.h"
#include "Highly_Experimental/Core/iop.h"
#include "Highly_Experimental/Core/r3000.h"
#include "Highly_Experimental/Core/spu.h"
#include "Highly_Experimental/Core/bios.h"

#include "Highly_Theoretical/Core/sega.h"

#include "Highly_Quixotic/Core/qsound.h"

#undef uint8
#undef uint16
#undef uint32

#include "mGBA/include/mgba/core/core.h"
#include "mGBA/include/mgba/core/blip_buf.h"
#include "mGBA/include/mgba-util/vfs.h"
#include "mGBA/include/mgba/core/log.h"

#include "lazyusf2/usf/usf.h"

#include "vio2sf/src/vio2sf/desmume/state.h"

#include "psflib/psflib.h"
#include "psflib/psf2fs.h"

#include "hebios.h"

#include <zlib.h>

# define strdup(s)							      \
  (__extension__							      \
    ({									      \
      const char *__old = (s);						      \
      size_t __len = strlen (__old) + 1;				      \
      char *__new = (char *) malloc (__len);			      \
      (char *) memcpy (__new, __old, __len);				      \
    }))

static int conf_play_forever = 0;

extern DB_decoder_t xsf_plugin;

#define trace(...) { fprintf(stderr, __VA_ARGS__); }
//#define trace(fmt,...)

static DB_functions_t *deadbeef;

#define min(x,y) ((x)<(y)?(x):(y))
#define max(x,y) ((x)>(y)?(x):(y))

#define BORK_TIME 0xC0CAC01A

inline unsigned get_be16( void const* p )
{
    return  (unsigned) ((unsigned char const*) p) [0] << 8 |
            (unsigned) ((unsigned char const*) p) [1];
}

inline unsigned get_le32( void const* p )
{
    return  (unsigned) ((unsigned char const*) p) [3] << 24 |
            (unsigned) ((unsigned char const*) p) [2] << 16 |
            (unsigned) ((unsigned char const*) p) [1] <<  8 |
            (unsigned) ((unsigned char const*) p) [0];
}

inline unsigned get_be32( void const* p )
{
    return  (unsigned) ((unsigned char const*) p) [0] << 24 |
            (unsigned) ((unsigned char const*) p) [1] << 16 |
            (unsigned) ((unsigned char const*) p) [2] <<  8 |
            (unsigned) ((unsigned char const*) p) [3];
}

void set_le32( void* p, unsigned n )
{
    ((unsigned char*) p) [0] = (unsigned char) n;
    ((unsigned char*) p) [1] = (unsigned char) (n >> 8);
    ((unsigned char*) p) [2] = (unsigned char) (n >> 16);
    ((unsigned char*) p) [3] = (unsigned char) (n >> 24);
}

static unsigned long parse_time_crap(const char *input)
{
    unsigned long value = 0;
    unsigned long multiplier = 1000;
    const char * ptr = input;
    unsigned long colon_count = 0;
    
    while (*ptr && ((*ptr >= '0' && *ptr <= '9') || *ptr == ':'))
    {
        colon_count += *ptr == ':';
        ++ptr;
    }
    if (colon_count > 2) return BORK_TIME;
    if (*ptr && *ptr != '.' && *ptr != ',') return BORK_TIME;
    if (*ptr) ++ptr;
    while (*ptr && *ptr >= '0' && *ptr <= '9') ++ptr;
    if (*ptr) return BORK_TIME;
    
    ptr = strrchr(input, ':');
    if (!ptr)
        ptr = input;
    for (;;)
    {
        char * end;
        if (ptr != input) ++ptr;
        if (multiplier == 1000)
        {
            double temp = strtod(ptr, &end);
            if (temp >= 60.0) return BORK_TIME;
            value = (long)(temp * 1000.0f);
        }
        else
        {
            unsigned long temp = strtoul(ptr, &end, 10);
            if (temp >= 60 && multiplier < 3600000) return BORK_TIME;
            value += temp * multiplier;
        }
        if (ptr == input) break;
        ptr -= 2;
        while (ptr > input && *ptr != ':') --ptr;
        multiplier *= 60;
    }
    
    return value;
}

struct psf_tag
{
    char * name;
    char * value;
    struct psf_tag * next;
};

static struct psf_tag * add_tag( struct psf_tag * tags, const char * name, const char * value )
{
    struct psf_tag * tag = (struct psf_tag *) malloc( sizeof( struct psf_tag ) );
    if ( !tag ) return tags;

    tag->name = strdup( name );
    if ( !tag->name ) {
        free( tag );
        return tags;
    }
    tag->value = strdup( value );
    if ( !tag->value ) {
        free( tag->name );
        free( tag );
        return tags;
    }
    tag->next = tags;
    return tag;
}

static void free_tags( struct psf_tag * tags )
{
    struct psf_tag * tag, * next;

    tag = tags;

    while ( tag )
    {
        next = tag->next;
        free( tag->name );
        free( tag->value );
        free( tag );
        tag = next;
    }
}

struct psf_info_meta_state
{
    int tag_song_ms;
    int tag_fade_ms;
    
    int utf8;
    
    struct psf_tag *tags;
};

typedef struct {
    uint32_t pc0;
    uint32_t gp0;
    uint32_t t_addr;
    uint32_t t_size;
    uint32_t d_addr;
    uint32_t d_size;
    uint32_t b_addr;
    uint32_t b_size;
    uint32_t s_ptr;
    uint32_t s_size;
    uint32_t sp,fp,gp,ret,base;
} exec_header_t;

typedef struct {
    char key[8];
    uint32_t text;
    uint32_t data;
    exec_header_t exec;
    char title[60];
} psxexe_hdr_t;

struct psf1_load_state
{
    void * emu;
    bool first;
    unsigned refresh;
};

static int psf1_info(void * context, const char * name, const char * value)
{
    psf1_load_state * state = ( psf1_load_state * ) context;
    
    if ( !state->refresh && !strcasecmp(name, "_refresh") )
    {
        state->refresh = atoi( value );
    }
    
    return 0;
}

int psf1_load(void * context, const uint8_t * exe, size_t exe_size,
              const uint8_t * reserved, size_t reserved_size)
{
    psf1_load_state * state = ( psf1_load_state * ) context;
    
    psxexe_hdr_t *psx = (psxexe_hdr_t *) exe;
    
    if ( exe_size < 0x800 ) return -1;
    
    uint32_t addr = get_le32( &psx->exec.t_addr );
    uint32_t size = (uint32_t)exe_size - 0x800;
    
    addr &= 0x1fffff;
    if ( ( addr < 0x10000 ) || ( size > 0x1f0000 ) || ( addr + size > 0x200000 ) ) return -1;
    
    void * pIOP = psx_get_iop_state( state->emu );
    iop_upload_to_ram( pIOP, addr, exe + 0x800, size );
    
    if ( !state->refresh )
    {
        if (!strncasecmp((const char *) exe + 113, "Japan", 5)) state->refresh = 60;
        else if (!strncasecmp((const char *) exe + 113, "Europe", 6)) state->refresh = 50;
        else if (!strncasecmp((const char *) exe + 113, "North America", 13)) state->refresh = 60;
    }
    
    if ( state->first )
    {
        void * pR3000 = iop_get_r3000_state( pIOP );
        r3000_setreg(pR3000, R3000_REG_PC, get_le32( &psx->exec.pc0 ) );
        r3000_setreg(pR3000, R3000_REG_GEN+29, get_le32( &psx->exec.s_ptr ) );
        state->first = false;
    }
    
    return 0;
}

static int EMU_CALL virtual_readfile(void *context, const char *path, int offset, char *buffer, int length)
{
    return psf2fs_virtual_readfile(context, path, offset, buffer, length);
}

struct sdsf_loader_state
{
    uint8_t * data;
    size_t data_size;
};

int sdsf_loader(void * context, const uint8_t * exe, size_t exe_size,
                const uint8_t * reserved, size_t reserved_size)
{
    if ( exe_size < 4 ) return -1;
    
    struct sdsf_loader_state * state = ( struct sdsf_loader_state * ) context;
    
    uint8_t * dst = state->data;
    
    if ( state->data_size < 4 ) {
        state->data = dst = ( uint8_t * ) malloc( exe_size );
        state->data_size = exe_size;
        memcpy( dst, exe, exe_size );
        return 0;
    }
    
    uint32_t dst_start = get_le32( dst );
    uint32_t src_start = get_le32( exe );
    dst_start &= 0x7fffff;
    src_start &= 0x7fffff;
    size_t dst_len = state->data_size - 4;
    size_t src_len = exe_size - 4;
    if ( dst_len > 0x800000 ) dst_len = 0x800000;
    if ( src_len > 0x800000 ) src_len = 0x800000;
    
    if ( src_start < dst_start )
    {
        uint32_t diff = dst_start - src_start;
        state->data_size = dst_len + 4 + diff;
        state->data = dst = ( uint8_t * ) realloc( dst, state->data_size );
        memmove( dst + 4 + diff, dst + 4, dst_len );
        memset( dst + 4, 0, diff );
        dst_len += diff;
        dst_start = src_start;
        set_le32( dst, dst_start );
    }
    if ( ( src_start + src_len ) > ( dst_start + dst_len ) )
    {
        size_t diff = ( src_start + src_len ) - ( dst_start + dst_len );
        state->data_size = dst_len + 4 + diff;
        state->data = dst = ( uint8_t * ) realloc( dst, state->data_size );
        memset( dst + 4 + dst_len, 0, diff );
    }
    
    memcpy( dst + 4 + ( src_start - dst_start ), exe + 4, src_len );
    
    return 0;
}

struct qsf_loader_state
{
    uint8_t * key;
    uint32_t key_size;

    uint8_t * z80_rom;
    uint32_t z80_size;

    uint8_t * sample_rom;
    uint32_t sample_size;
};

static int psf_info_meta(void * context, const char * name, const char * value)
{
    struct psf_info_meta_state * state = ( struct psf_info_meta_state * ) context;

    if ( !strcasecmp( name, "length" ) )
    {
        unsigned long n = parse_time_crap( value );
        if ( n != BORK_TIME ) state->tag_song_ms = n;
    }
    else if ( !strcasecmp( name, "fade" ) )
    {
        unsigned long n = parse_time_crap( value );
        if ( n != BORK_TIME ) state->tag_fade_ms = n;
    }
    else if ( !strcasecmp( name, "utf8" ) )
    {
        state->utf8 = 1;
    }
    else if ( *name != '_' )
    {
        if ( !strcasecmp( name, "game" ) ) name = "album";
        else if ( !strcasecmp( name, "year" ) ) name = "date";
        else if ( !strcasecmp( name, "tracknumber" ) ) name = "track";
        else if ( !strcasecmp( name, "discnumber" ) ) name = "disc";

        state->tags = add_tag( state->tags, name, value );
    }

    return 0;
}

static int qsf_upload_section( struct qsf_loader_state * state, const char * section, uint32_t start,
                           const uint8_t * data, uint32_t size )
{
    uint8_t ** array = NULL;
    uint32_t * array_size = NULL;
    uint32_t max_size = 0x7fffffff;

    if ( !strcmp( section, "KEY" ) ) { array = &state->key; array_size = &state->key_size; max_size = 11; }
    else if ( !strcmp( section, "Z80" ) ) { array = &state->z80_rom; array_size = &state->z80_size; }
    else if ( !strcmp( section, "SMP" ) ) { array = &state->sample_rom; array_size = &state->sample_size; }
    else return -1;

    if ( ( start + size ) < start ) return -1;

    uint32_t new_size = start + size;
    uint32_t old_size = *array_size;
    if ( new_size > max_size ) return -1;

    if ( new_size > old_size ) {
        *array = (uint8_t *) realloc( *array, new_size );
        *array_size = new_size;
        memset( *array + old_size, 0, new_size - old_size );
    }

    memcpy( *array + start, data, size );

    return 0;
}

static int qsf_load(void * context, const uint8_t * exe, size_t exe_size,
                                    const uint8_t * reserved, size_t reserved_size)
{
    struct qsf_loader_state * state = ( struct qsf_loader_state * ) context;

    for (;;) {
        char s[4];
        if ( exe_size < 11 ) break;
        memcpy( s, exe, 3 ); exe += 3; exe_size -= 3;
        s [3] = 0;
        uint32_t dataofs  = get_le32( exe ); exe += 4; exe_size -= 4;
        uint32_t datasize = get_le32( exe ); exe += 4; exe_size -= 4;
        if ( datasize > exe_size )
            return -1;

        if ( qsf_upload_section( state, s, dataofs, exe, datasize ) < 0 )
            return -1;

        exe += datasize;
        exe_size -= datasize;
    }

    return 0;
}

struct gsf_loader_state
{
    int entry_set;
    uint32_t entry;
    uint8_t * data;
    size_t data_size;
};

static int gsf_loader(void * context, const uint8_t * exe, size_t exe_size,
                      const uint8_t * reserved, size_t reserved_size)
{
    if ( exe_size < 12 ) return -1;
    
    struct gsf_loader_state * state = ( struct gsf_loader_state * ) context;
    
    unsigned char *iptr;
    size_t isize;
    unsigned char *xptr;
    unsigned xentry = get_le32(exe + 0);
    unsigned xsize = get_le32(exe + 8);
    unsigned xofs = get_le32(exe + 4) & 0x1ffffff;
    if ( xsize < exe_size - 12 ) return -1;
    if (!state->entry_set)
    {
        state->entry = xentry;
        state->entry_set = 1;
    }
    {
        iptr = state->data;
        isize = state->data_size;
        state->data = 0;
        state->data_size = 0;
    }
    if (!iptr)
    {
        size_t rsize = xofs + xsize;
        {
            rsize -= 1;
            rsize |= rsize >> 1;
            rsize |= rsize >> 2;
            rsize |= rsize >> 4;
            rsize |= rsize >> 8;
            rsize |= rsize >> 16;
            rsize += 1;
        }
        iptr = (unsigned char *) malloc(rsize + 10);
        if (!iptr)
            return -1;
        memset(iptr, 0, rsize + 10);
        isize = rsize;
    }
    else if (isize < xofs + xsize)
    {
        size_t rsize = xofs + xsize;
        {
            rsize -= 1;
            rsize |= rsize >> 1;
            rsize |= rsize >> 2;
            rsize |= rsize >> 4;
            rsize |= rsize >> 8;
            rsize |= rsize >> 16;
            rsize += 1;
        }
        xptr = (unsigned char *) realloc(iptr, xofs + rsize + 10);
        if (!xptr)
        {
            free(iptr);
            return -1;
        }
        iptr = xptr;
        isize = rsize;
    }
    memcpy(iptr + xofs, exe + 12, xsize);
    {
        state->data = iptr;
        state->data_size = isize;
    }
    return 0;
}

struct gsf_running_state
{
    struct mAVStream stream;
    void * rom;
    int16_t samples[2048 * 2];
    int buffered;
};

static void _gsf_postAudioBuffer(struct mAVStream * stream, blip_t * left, blip_t * right)
{
    struct gsf_running_state * state = ( struct gsf_running_state * ) stream;
    blip_read_samples(left, state->samples, 2048, true);
    blip_read_samples(right, state->samples + 1, 2048, true);
    state->buffered = 2048;
}

struct usf_loader_state
{
    uint32_t enablecompare;
    uint32_t enablefifofull;
    
    void * emu_state;
};

static int usf_loader(void * context, const uint8_t * exe, size_t exe_size,
                      const uint8_t * reserved, size_t reserved_size)
{
    struct usf_loader_state * uUsf = ( struct usf_loader_state * ) context;
    if ( exe && exe_size > 0 ) return -1;
    
    return usf_upload_section( uUsf->emu_state, reserved, reserved_size );
}

static int usf_info(void * context, const char * name, const char * value)
{
    struct usf_loader_state * uUsf = ( struct usf_loader_state * ) context;
    
    if ( !strcasecmp( name, "_enablecompare" ) && strlen( value ) )
        uUsf->enablecompare = 1;
    else if ( !strcasecmp( name, "_enablefifofull" ) && strlen( value ) )
        uUsf->enablefifofull = 1;
    
    return 0;
}

struct twosf_loader_state
{
    uint8_t * rom;
    uint8_t * state;
    size_t rom_size;
    size_t state_size;
    
    int initial_frames;
    int sync_type;
    int clockdown;
    int arm9_clockdown_level;
    int arm7_clockdown_level;
    
    twosf_loader_state()
    : rom(0), state(0), rom_size(0), state_size(0),
    initial_frames(-1), sync_type(0), clockdown(0),
    arm9_clockdown_level(0), arm7_clockdown_level(0)
    {
    }
    
    ~twosf_loader_state()
    {
        if (rom) free(rom);
        if (state) free(state);
    }
};

static int load_twosf_map(struct twosf_loader_state *state, int issave, const unsigned char *udata, unsigned usize)
{
    if (usize < 8) return -1;
    
    unsigned char *iptr;
    size_t isize;
    unsigned char *xptr;
    unsigned xsize = get_le32(udata + 4);
    unsigned xofs = get_le32(udata + 0);
    if (issave)
    {
        iptr = state->state;
        isize = state->state_size;
        state->state = 0;
        state->state_size = 0;
    }
    else
    {
        iptr = state->rom;
        isize = state->rom_size;
        state->rom = 0;
        state->rom_size = 0;
    }
    if (!iptr)
    {
        size_t rsize = xofs + xsize;
        if (!issave)
        {
            rsize -= 1;
            rsize |= rsize >> 1;
            rsize |= rsize >> 2;
            rsize |= rsize >> 4;
            rsize |= rsize >> 8;
            rsize |= rsize >> 16;
            rsize += 1;
        }
        iptr = (unsigned char *) malloc(rsize + 10);
        if (!iptr)
            return -1;
        memset(iptr, 0, rsize + 10);
        isize = rsize;
    }
    else if (isize < xofs + xsize)
    {
        size_t rsize = xofs + xsize;
        if (!issave)
        {
            rsize -= 1;
            rsize |= rsize >> 1;
            rsize |= rsize >> 2;
            rsize |= rsize >> 4;
            rsize |= rsize >> 8;
            rsize |= rsize >> 16;
            rsize += 1;
        }
        xptr = (unsigned char *) realloc(iptr, xofs + rsize + 10);
        if (!xptr)
        {
            free(iptr);
            return -1;
        }
        iptr = xptr;
        isize = rsize;
    }
    memcpy(iptr + xofs, udata + 8, xsize);
    if (issave)
    {
        state->state = iptr;
        state->state_size = isize;
    }
    else
    {
        state->rom = iptr;
        state->rom_size = isize;
    }
    return 0;
}

static int load_twosf_mapz(struct twosf_loader_state *state, int issave, const unsigned char *zdata, unsigned zsize, unsigned zcrc)
{
    int ret;
    int zerr;
    uLongf usize = 8;
    uLongf rsize = usize;
    unsigned char *udata;
    unsigned char *rdata;
    
    udata = (unsigned char *) malloc(usize);
    if (!udata)
        return -1;
    
    while (Z_OK != (zerr = uncompress(udata, &usize, zdata, zsize)))
    {
        if (Z_MEM_ERROR != zerr && Z_BUF_ERROR != zerr)
        {
            free(udata);
            return -1;
        }
        if (usize >= 8)
        {
            usize = get_le32(udata + 4) + 8;
            if (usize < rsize)
            {
                rsize += rsize;
                usize = rsize;
            }
            else
                rsize = usize;
        }
        else
        {
            rsize += rsize;
            usize = rsize;
        }
        rdata = (unsigned char *) realloc(udata, usize);
        if (!rdata)
        {
            free(udata);
            return -1;
        }
        udata = rdata;
    }
    
    rdata = (unsigned char *) realloc(udata, usize);
    if (!rdata)
    {
        free(udata);
        return -1;
    }
    
    if (0)
    {
        uLong ccrc = crc32(crc32(0L, Z_NULL, 0), rdata, (uInt) usize);
        if (ccrc != zcrc)
            return -1;
    }
    
    ret = load_twosf_map(state, issave, rdata, (unsigned) usize);
    free(rdata);
    return ret;
}

static int twosf_loader(void * context, const uint8_t * exe, size_t exe_size,
                        const uint8_t * reserved, size_t reserved_size)
{
    struct twosf_loader_state * state = ( struct twosf_loader_state * ) context;
    
    if ( exe_size >= 8 )
    {
        if ( load_twosf_map(state, 0, exe, (unsigned) exe_size) )
            return -1;
    }
    
    if ( reserved_size )
    {
        size_t resv_pos = 0;
        if ( reserved_size < 16 )
            return -1;
        while ( resv_pos + 12 < reserved_size )
        {
            unsigned save_size = get_le32(reserved + resv_pos + 4);
            unsigned save_crc = get_le32(reserved + resv_pos + 8);
            if (get_le32(reserved + resv_pos + 0) == 0x45564153)
            {
                if (resv_pos + 12 + save_size > reserved_size)
                    return -1;
                if (load_twosf_mapz(state, 1, reserved + resv_pos + 12, save_size, save_crc))
                    return -1;
            }
            resv_pos += 12 + save_size;
        }
    }
    
    return 0;
}

static int twosf_info(void * context, const char * name, const char * value)
{
    struct twosf_loader_state * state = ( struct twosf_loader_state * ) context;
    char *end;
    
    if ( !strcasecmp( name, "_frames" ) )
    {
        state->initial_frames = (int)strtol( value, &end, 10 );
    }
    else if ( !strcasecmp( name, "_clockdown" ) )
    {
        state->clockdown = (int)strtol( value, &end, 10 );
    }
    else if ( !strcasecmp( name, "_vio2sf_sync_type") )
    {
        state->sync_type = (int)strtol( value, &end, 10 );
    }
    else if ( !strcasecmp( name, "_vio2sf_arm9_clockdown_level" ) )
    {
        state->arm9_clockdown_level = (int)strtol( value, &end, 10 );
    }
    else if ( !strcasecmp( name, "_vio2sf_arm7_clockdown_level" ) )
    {
        state->arm7_clockdown_level = (int)strtol( value, &end, 10 );
    }
    
    return 0;
}

static void * psf_file_fopen( const char * uri )
{
    return deadbeef->fopen( uri );
}

static size_t psf_file_fread( void * buffer, size_t size, size_t count, void * handle )
{
    return deadbeef->fread( buffer, size, count, (DB_FILE *) handle );
}

static int psf_file_fseek( void * handle, int64_t offset, int whence )
{
    return deadbeef->fseek( (DB_FILE *) handle, offset, whence );
}

static int psf_file_fclose( void * handle )
{
    deadbeef->fclose( (DB_FILE *) handle );
    return 0;
}

static long psf_file_ftell( void * handle )
{
    return deadbeef->ftell( (DB_FILE *) handle );
}

const psf_file_callbacks psf_file_system =
{
    "\\/|:",
    psf_file_fopen,
    psf_file_fread,
    psf_file_fseek,
    psf_file_fclose,
    psf_file_ftell
};

typedef struct {
    DB_fileinfo_t info;
    const char *path;
    int version;
    void *emu;
    void *emu_extra;
    int samples_played;
    int samples_to_play;
    int samples_to_fade;
    int can_loop;
} psf_info_t;

DB_fileinfo_t *
psf_open (uint32_t hints) {
    DB_fileinfo_t *_info = (DB_fileinfo_t *)malloc (sizeof (psf_info_t));
    psf_info_t *info = (psf_info_t *)_info;
    memset (_info, 0, sizeof (psf_info_t));
    info->can_loop = hints & DDB_DECODER_HINT_CAN_LOOP;
    return _info;
}

int
get_srate(int version)
{
    switch (version)
    {
        case 1: case 0x11: case 0x12: case 0x21:
        case 0x22: case 0x24: case 0x25:
            return 44100;
            
        case 2:
            return 48000;

        case 0x41:
            return 24038;
    }
    return -1;
}

static void
emu_cleanup(psf_info_t *info)
{
    if (info->emu)
    {
        if (info->version == 0x21)
        {
            usf_shutdown(info->emu);
            free(info->emu);
        }
        else if (info->version == 0x22)
        {
            struct mCore * core = ( struct mCore * ) info->emu;
            core->deinit(core);
        }
        else if (info->version == 0x24)
        {
            NDS_state * state = (NDS_state *) info->emu;
            state_deinit(state);
            free(state);
        }
        else
        {
            free(info->emu);
        }
        info->emu = NULL;
    }
    if (info->emu_extra)
    {
        if (info->version == 0x02)
            psf2fs_delete(info->emu_extra);
        else if (info->version == 0x22)
        {
            struct gsf_running_state * rstate = ( struct gsf_running_state * ) info->emu_extra;
            free( rstate->rom );
            free( rstate );
        }
        else if (info->version == 0x24)
            free(info->emu_extra);
        else if (info->version == 0x41)
        {
            struct qsf_loader_state * state = (struct qsf_loader_state *) info->emu_extra;
            free(state->key);
            free(state->z80_rom);
            free(state->sample_rom);
            free(state);
        }
        info->emu_extra = NULL;
    }
}

static void
psf_error_log(void * unused, const char * message) {
    fprintf(stderr, "%s", message);
}

static int
emu_init(psf_info_t *info) {
    emu_cleanup(info);
    
    if (info->version == 1 || info->version == 2)
    {
        info->emu = malloc(psx_get_state_size(info->version));
        
        if (!info->emu)
        {
            trace( "psf: out of memory\n" );
            return -1;
        }
        
        psx_clear_state(info->emu, info->version);
        
        if (info->version == 1)
        {
            psf1_load_state state;
            
            state.emu = info->emu;
            state.first = true;
            state.refresh = 0;
            
            if (psf_load(info->path, &psf_file_system, 1, psf1_load, &state, psf1_info, &state, 1, psf_error_log, 0) <= 0)
            {
                trace( "psf: invalid PSF file\n" );
                return -1;
            }
            
            if (state.refresh)
                psx_set_refresh(info->emu, state.refresh);
        }
        else if (info->version == 2)
        {
            info->emu_extra = psf2fs_create();
            if (!info->emu_extra)
            {
                trace( "psf: out of memory\n" );
                return -1;
            }
            
            psf1_load_state state;
            
            state.refresh = 0;
            
            if (psf_load(info->path, &psf_file_system, 2, psf2fs_load_callback, info->emu_extra, psf1_info, &state, 1, psf_error_log, 0) <= 0)
            {
                trace( "psf: invalid PSF file\n" );
                return -1;
            }
            
            if (state.refresh)
                psx_set_refresh(info->emu, state.refresh);
            
            psx_set_readfile(info->emu, virtual_readfile, info->emu_extra);
        }
    }
    else if (info->version == 0x11 || info->version == 0x12)
    {
        struct sdsf_loader_state state;
        memset(&state, 0, sizeof(state));
        
        if (psf_load(info->path, &psf_file_system, info->version, sdsf_loader, &state, 0, 0, 0, psf_error_log, 0) <= 0)
        {
            trace( "psf: invalid PSF file\n" );
            return -1;
        }
        
        info->emu = malloc(sega_get_state_size(info->version - 0x10));
        
        if (!info->emu)
        {
            trace( "psf: out of memory\n" );
            free(state.data);
            return -1;
        }
        
        sega_clear_state(info->emu, info->version - 0x10);
        
        sega_enable_dry(info->emu, 1);
        sega_enable_dsp(info->emu, 1);
        
        sega_enable_dsp_dynarec(info->emu, 0);
        
        uint32_t start = get_le32(state.data);
        size_t length = state.data_size;
        const size_t max_length = (info->version == 0x12) ? 0x800000 : 0x80000;
        if ((start + (length - 4)) > max_length)
            length = max_length - start + 4;
        sega_upload_program(info->emu, state.data, (uint32_t)length);
        
        free(state.data);
    }
    else if (info->version == 0x21)
    {
        struct usf_loader_state state;
        memset(&state, 0, sizeof(state));
        
        state.emu_state = malloc(usf_get_state_size());
        if (!state.emu_state)
        {
            trace( "psf: out of memory\n" );
            return -1;
        }
        
        usf_clear(state.emu_state);
        
        usf_set_hle_audio(state.emu_state, 1);
        
        info->emu = (void *) state.emu_state;
        
        if (psf_load(info->path, &psf_file_system, 0x21, usf_loader, &state, usf_info, &state, 1, psf_error_log, 0) <= 0)
        {
            trace( "psf: invalid PSF file\n" );
            return -1;
        }
        
        usf_set_compare(state.emu_state, state.enablecompare);
        usf_set_fifo_full(state.emu_state, state.enablefifofull);
    }
    else if (info->version == 0x22)
    {
        struct gsf_loader_state state;
        memset(&state, 0, sizeof(state));
        
        if (psf_load(info->path, &psf_file_system, 0x22, gsf_loader, &state, 0, 0, 0, psf_error_log, 0) <= 0)
        {
            trace( "psf: invalid PSF file\n" );
            return -1;
        }
        
        if (state.data_size > UINT_MAX)
        {
            trace( "psf: GSF ROM image too large\n" );
            free(state.data);
            return -1;
        }
        
        struct VFile * rom = VFileFromConstMemory(state.data, state.data_size);
        if ( !rom )
        {
            free( state.data );
            trace( "psf: unable to load ROM\n" );
            return -1;
        }
        
        struct mCore * core = mCoreFindVF( rom );
        if ( !core )
        {
            free(state.data);
            trace( "psf: unable to find GBA core\n" );
            return -1;
        }
        
        struct gsf_running_state * rstate = (struct gsf_running_state *) calloc(1, sizeof(struct gsf_running_state));
        if ( !rstate )
        {
            core->deinit(core);
            free(state.data);
            trace( "psf: out of memory\n" );
            return -1;
        }
        
        rstate->rom = state.data;
        rstate->stream.postAudioBuffer = _gsf_postAudioBuffer;
        
        core->init(core);
        core->setAVStream(core, &rstate->stream);
        mCoreInitConfig(core, NULL);
        
        core->setAudioBufferSize(core, 2048);
        
        blip_set_rates(core->getAudioChannel(core, 0), core->frequency(core), 44100);
        blip_set_rates(core->getAudioChannel(core, 1), core->frequency(core), 44100);
        
        struct mCoreOptions opts = {
            .skipBios = true,
            .useBios = false,
            .sampleRate = 44100,
            .volume = 0x100,
        };
        
        mCoreConfigLoadDefaults(&core->config, &opts);
        
        core->loadROM(core, rom);
        core->reset(core);

        info->emu = (void *) core;
        info->emu_extra = (void *) rstate;
    }
    else if (info->version == 0x24)
    {
        struct twosf_loader_state state;
        memset(&state, 0, sizeof(state));
        
        NDS_state * nds_state = (NDS_state *) calloc(1, sizeof(*nds_state));
        if (!nds_state)
        {
            trace( "psf: out of memory\n" );
            return -1;
        }
        
        info->emu = (void *) nds_state;
        
        if (state_init(nds_state))
        {
            trace( "psf: out of memory\n" );
            return -1;
        }
        
        if (psf_load(info->path, &psf_file_system, 0x24, twosf_loader, &state, twosf_info, &state, 1, psf_error_log, 0) <= 0)
        {
            trace( "psf: invalid PSF file\n" );
            return -1;
        }
        
        if (!state.arm7_clockdown_level)
            state.arm7_clockdown_level = state.clockdown;
        if (!state.arm9_clockdown_level)
            state.arm9_clockdown_level = state.clockdown;
        
        nds_state->dwInterpolation = 1;
        nds_state->dwChannelMute = 0;
        
        nds_state->initial_frames = state.initial_frames;
        nds_state->sync_type = state.sync_type;
        nds_state->arm7_clockdown_level = state.arm7_clockdown_level;
        nds_state->arm9_clockdown_level = state.arm9_clockdown_level;
        
        if (state.rom)
            state_setrom(nds_state, state.rom, (u32)state.rom_size, 0);
        
        state_loadstate(nds_state, state.state, (u32)state.state_size);
        
        info->emu_extra = state.rom;
        state.rom = 0; // So twosf_loader_state doesn't free it when it goes out of scope
    }
    else if (info->version == 0x41)
    {
        struct qsf_loader_state * state = (struct qsf_loader_state *) calloc(1, sizeof(*state));
        
        if (!state)
        {
            trace( "psf: out of memory\n" );
            return -1;
        }
        
        info->emu_extra = (void *) state;
        
        if ( psf_load(info->path, &psf_file_system, 0x41, qsf_load, state, 0, 0, 0, psf_error_log, 0) <= 0 ) {
            trace( "psf: invalid PSF file\n" );
            return -1;
        }
        
        info->emu = malloc(qsound_get_state_size());
        if (!info->emu) {
            trace( "psf: out of memory\n" );
            return -1;
        }
        
        qsound_clear_state(info->emu);
        
        if(state->key_size == 11) {
            uint8_t * ptr = state->key;
            uint32_t swap_key1 = get_be32(ptr +  0);
            uint32_t swap_key2 = get_be32(ptr +  4);
            uint32_t addr_key  = get_be16(ptr +  8);
            uint8_t  xor_key   =        *(ptr + 10);
            qsound_set_kabuki_key(info->emu, swap_key1, swap_key2, addr_key, xor_key);
        } else {
            qsound_set_kabuki_key(info->emu, 0, 0, 0, 0);
        }
        qsound_set_z80_rom(info->emu, state->z80_rom, state->z80_size);
        qsound_set_sample_rom(info->emu, state->sample_rom, state->sample_size);
    }
    else
    {
        trace( "psf: unsupported PSF version %d\n", info->version );
        return -1;
    }
    
    return 0;
}

int
psf_init (DB_fileinfo_t *_info, DB_playItem_t *it) {
    psf_info_t *info = (psf_info_t *)_info;

    deadbeef->pl_lock ();
    const char * uri = info->path = strdup( deadbeef->pl_find_meta (it, ":URI") );
    deadbeef->pl_unlock ();
    
    struct psf_info_meta_state info_state;
    memset(&info_state, 0, sizeof(info_state));
    
    int psf_version = psf_load(uri, &psf_file_system, 0, 0, 0, psf_info_meta, &info_state, 0, psf_error_log, 0);
    if (psf_version < 0) {
        trace ("psf: failed to open %s\n", uri);
        return -1;
    }
    
    free_tags(info_state.tags);

    info->version = psf_version;
    
    if (emu_init(info) < 0)
        return -1;
    
    int tag_song_ms = info_state.tag_song_ms;
    int tag_fade_ms = info_state.tag_fade_ms;

    if (!tag_song_ms)
    {
        tag_song_ms = ( 2 * 60 + 50 ) * 1000;
        tag_fade_ms =            10   * 1000;
    }

    const int srate = get_srate(psf_version);

    info->samples_played = 0;
    info->samples_to_play = (int)((uint64_t)tag_song_ms * (uint64_t)srate / 1000);
    info->samples_to_fade = (int)((uint64_t)tag_fade_ms * (uint64_t)srate / 1000);

    _info->plugin = &xsf_plugin;
    _info->fmt.channels = 2;
    _info->fmt.bps = 16;
    _info->fmt.samplerate = srate;
    _info->fmt.channelmask = _info->fmt.channels == 1 ? DDB_SPEAKER_FRONT_LEFT : (DDB_SPEAKER_FRONT_LEFT | DDB_SPEAKER_FRONT_RIGHT);
    _info->readpos = 0;

    return 0;
}

void
psf_free (DB_fileinfo_t *_info) {
    psf_info_t *info = (psf_info_t *)_info;
    if (info) {
        emu_cleanup(info);
        if (info->path) {
            free ((void *) info->path);
            info->path = NULL;
        }
        free (info);
    }
}

int
do_render_samples(psf_info_t *info, int16_t * buf, unsigned & count)
{
    int err = 0;
    const char * errmsg;
    switch (info->version)
    {
        case 1:
        case 2:
            err = psx_execute( info->emu, 0x7FFFFFFF, buf, & count, 0 );
            if ( err == -2 ) trace( "Execution halted with an error." );
            break;
            
        case 0x11:
        case 0x12:
            err = sega_execute( info->emu, 0x7FFFFFFF, buf, & count );
            break;
            
        case 0x21:
            errmsg = usf_render_resampled( info->emu, buf, count, 44100 );
            if (errmsg)
            {
                trace("%s\n", errmsg);
                err = -1;
            }
            break;
            
        case 0x22:
        {
            struct mCore * core = ( struct mCore * ) info->emu;
            struct gsf_running_state * rstate = ( struct gsf_running_state * ) info->emu_extra;
            
            unsigned long frames_to_render = count;
            
            do
            {
                unsigned long frames_rendered = rstate->buffered;
                
                if ( frames_rendered >= frames_to_render )
                {
                    if (buf) memcpy( buf, rstate->samples, frames_to_render * 4 );
                    frames_rendered -= frames_to_render;
                    memcpy( rstate->samples, rstate->samples + frames_to_render * 2, frames_rendered * 4 );
                    frames_to_render = 0;
                }
                else
                {
                    if (buf)
                    {
                        memcpy( buf, rstate->samples, frames_rendered * 4 );
                        buf = (int16_t *)(((uint8_t *) buf) + frames_rendered * 4);
                    }
                    frames_to_render -= frames_rendered;
                    frames_rendered = 0;
                }
                rstate->buffered = (int) frames_rendered;
                
                if (frames_to_render)
                {
                    while ( !rstate->buffered )
                        core->runFrame(core);
                }
            }
            while (frames_to_render);
            count -= (unsigned) frames_to_render;
        }
            break;
            
        case 0x24:
            state_render( (NDS_state *)info->emu, buf, count );
            break;
            
        case 0x41:
            err = qsound_execute( info->emu, 0x7FFFFFFF, buf, &count );
            break;
    }
    if ( !count ) return -1;
    return err;
}

int
psf_read (DB_fileinfo_t *_info, char *bytes, int size) {
    psf_info_t *info = (psf_info_t *)_info;
    short * samples = (short *) bytes;
    uint32_t sample_count = size / ( 2 * sizeof(short) );
    int play_forever = conf_play_forever && info->can_loop;

    if ( !play_forever && info->samples_played >= info->samples_to_play + info->samples_to_fade ) {
        return -1;
    }

    if (do_render_samples(info, samples, sample_count) < 0) {
        trace ( "psf: execution error\n" );
        return -1;
    }

    int samples_start = info->samples_played;
    int samples_end   = info->samples_played += sample_count;

    if ( !play_forever && ( samples && ( samples_end > info->samples_to_play ) ) )
    {
        int fade_start = info->samples_to_play;
        if ( fade_start < samples_start ) fade_start = samples_start;
        int samples_length = info->samples_to_play + info->samples_to_fade;
        int fade_end = samples_length;
        if ( fade_end > samples_end ) fade_end = samples_end;

        for ( int i = fade_start; i < fade_end; i++ )
        {
            samples[ ( i - samples_start ) * 2 + 0 ] = (int64_t)samples[ ( i - samples_start ) * 2 + 0 ] * ( samples_length - i ) / info->samples_to_fade;
            samples[ ( i - samples_start ) * 2 + 1 ] = (int64_t)samples[ ( i - samples_start ) * 2 + 1 ] * ( samples_length - i ) / info->samples_to_fade;
        }

        if ( samples_end > samples_length ) samples_end = samples_length;
    }

    return ( samples_end - samples_start ) * 2 * sizeof(short);
}

int
psf_seek_sample (DB_fileinfo_t *_info, int sample) {
    psf_info_t *info = (psf_info_t *)_info;
    unsigned long int s = sample;
    if (s < info->samples_played) {
        if (emu_init(info) < 0)
            return -1;

        info->samples_played = 0;
    }
    while ( info->samples_played < s ) {
        unsigned long to_skip = s - info->samples_played;
        if ( to_skip > 1024 ) to_skip = 1024;
        if ( psf_read( _info, NULL, (int)(to_skip * 2 * sizeof(short)) ) < 0 ) {
            return -1;
        }
    }
    _info->readpos = s/(float)_info->fmt.samplerate;
    return 0;
}

int
psf_seek (DB_fileinfo_t *_info, float time) {
    return psf_seek_sample (_info, time * _info->fmt.samplerate);
}

static const char *
convstr (const char* str, int sz, char *out, int out_sz) {
    int i;
    for (i = 0; i < sz; i++) {
        if (str[i] != ' ') {
            break;
        }
    }
    if (i == sz) {
        out[0] = 0;
        return out;
    }

    const char *cs = deadbeef->junk_detect_charset (str);
    if (!cs) {
        return str;
    }
    else {
        if (deadbeef->junk_iconv (str, sz, out, out_sz, cs, "utf-8") >= 0) {
            return out;
        }
    }

    trace ("psf: failed to detect charset\n");
    return NULL;
}

DB_playItem_t *
psf_insert (ddb_playlist_t *plt, DB_playItem_t *after, const char *fname) {
    DB_playItem_t *it = NULL;

    struct psf_info_meta_state state;
    memset( &state, 0, sizeof(state) );

    int psf_version = psf_load( fname, &psf_file_system, 0, 0, 0, psf_info_meta, &state, 0, psf_error_log, 0 );

    if ( psf_version < 0 )
        return after;

    int tag_song_ms = state.tag_song_ms;
    int tag_fade_ms = state.tag_fade_ms;

    if (!tag_song_ms)
    {
        tag_song_ms = ( 2 * 60 + 50 ) * 1000;
        tag_fade_ms =            10   * 1000;
    }

    it = deadbeef->pl_item_alloc_init (fname, xsf_plugin.plugin.id);

    char junk_buffer[2][1024];

    struct psf_tag * tag = state.tags;
    while ( tag ) {
        if ( !strncasecmp( tag->name, "replaygain_", 11 ) ) {
            double fval = atof( tag->value );
            if ( !strcasecmp( tag->name + 11, "album_gain" ) ) {
                deadbeef->pl_set_item_replaygain( it, DDB_REPLAYGAIN_ALBUMGAIN, fval );
            } else if ( !strcasecmp( tag->name + 11, "album_peak" ) ) {
                deadbeef->pl_set_item_replaygain( it, DDB_REPLAYGAIN_ALBUMPEAK, fval );
            } else if ( !strcasecmp( tag->name + 11, "track_gain" ) ) {
                deadbeef->pl_set_item_replaygain( it, DDB_REPLAYGAIN_TRACKGAIN, fval );
            } else if ( !strcasecmp( tag->name + 11, "track_peak" ) ) {
                deadbeef->pl_set_item_replaygain( it, DDB_REPLAYGAIN_TRACKPEAK, fval );
            }
        } else {
            if ( !state.utf8 ) {
                junk_buffer[0][ 1023 ] = '\0';
                junk_buffer[1][ 1023 ] = '\0';
                deadbeef->pl_add_meta (it, convstr( tag->name, (int) strlen( tag->name ), junk_buffer[0], 1023 ),
                        convstr( tag->value, (int) strlen( tag->value ), junk_buffer[1], 1023 ));
            } else {
                deadbeef->pl_add_meta (it, tag->name, tag->value);
            }
        }
        tag = tag->next;
    }
    free_tags( state.tags );

    deadbeef->plt_set_item_duration (plt, it, (float)(tag_song_ms + tag_fade_ms) / 1000.f);
    deadbeef->pl_add_meta (it, ":FILETYPE", "PSF");
    after = deadbeef->plt_insert_item (plt, after, it);
    deadbeef->pl_item_unref (it);
    return after;
}

int
psf_read_metadata (DB_playItem_t *it) {
    struct psf_info_meta_state state;
    memset( &state, 0, sizeof(state) );
    
    deadbeef->pl_lock ();
    int psf_version = psf_load( deadbeef->pl_find_meta (it, ":URI"), &psf_file_system, 0, 0, 0, psf_info_meta, &state, 0, psf_error_log, 0 );
    deadbeef->pl_unlock ();
    
    if ( psf_version < 0 )
        return -1;

    deadbeef->pl_delete_all_meta (it);

    int tag_song_ms = state.tag_song_ms;
    int tag_fade_ms = state.tag_fade_ms;
    
    if (!tag_song_ms)
    {
        tag_song_ms = ( 2 * 60 + 50 ) * 1000;
        tag_fade_ms =            10   * 1000;
    }
    
    char junk_buffer[2][1024];
    
    struct psf_tag * tag = state.tags;
    while ( tag ) {
        if ( !strncasecmp( tag->name, "replaygain_", 11 ) ) {
            double fval = atof( tag->value );
            if ( !strcasecmp( tag->name + 11, "album_gain" ) ) {
                deadbeef->pl_set_item_replaygain( it, DDB_REPLAYGAIN_ALBUMGAIN, fval );
            } else if ( !strcasecmp( tag->name + 11, "album_peak" ) ) {
                deadbeef->pl_set_item_replaygain( it, DDB_REPLAYGAIN_ALBUMPEAK, fval );
            } else if ( !strcasecmp( tag->name + 11, "track_gain" ) ) {
                deadbeef->pl_set_item_replaygain( it, DDB_REPLAYGAIN_TRACKGAIN, fval );
            } else if ( !strcasecmp( tag->name + 11, "track_peak" ) ) {
                deadbeef->pl_set_item_replaygain( it, DDB_REPLAYGAIN_TRACKPEAK, fval );
            }
        } else {
            if ( !state.utf8 ) {
                junk_buffer[0][ 1023 ] = '\0';
                junk_buffer[1][ 1023 ] = '\0';
                deadbeef->pl_add_meta (it, convstr( tag->name, (int) strlen( tag->name ), junk_buffer[0], 1023 ),
                                       convstr( tag->value, (int) strlen( tag->value ), junk_buffer[1], 1023 ));
            } else {
                deadbeef->pl_add_meta (it, tag->name, tag->value);
            }
        }
        tag = tag->next;
    }
    free_tags( state.tags );

    ddb_playlist_t *plt = deadbeef->pl_get_playlist (it);
    deadbeef->plt_set_item_duration (plt, it, (float)(tag_song_ms + tag_fade_ms) / 1000.f);
    deadbeef->pl_add_meta (it, ":FILETYPE", "PSF");

    return 0;
}

static void
format_float(char * out, float in, const char * tail) {
    int ival = (int)(in * 100.0f);
    sprintf(out, "%d.%02d", ival / 100, ival % 100);
    if (tail) strcat(out, tail);
}

static void
format_tag(char * out, const char * key, const char * value) {
    const char * newline = strchr(value, '\n');
    while (newline) {
        strcpy(out, key);
        out += strlen(key);
        *out++ = '=';
        for (const char * ptr = value; ptr <= newline; ++ptr) {
            *out++ = *ptr;
        }
        value = newline + 1;
        newline = strchr(value, '\n');
    }
    strcpy(out, key);
    out += strlen(key);
    *out++ = '=';
    strcpy(out, value);
}

int
psf_write_metadata (DB_playItem_t *it) {
    int err = -1;
    char fname[PATH_MAX];
    char tmppath[PATH_MAX];
    int psf_version;
    struct psf_info_meta_state state = {0};
    DB_FILE *fp = NULL;
    char *buffer = NULL;
    struct stat stat_struct;
    int out = -1;
    uint32_t reserved_size, exe_compressed_size;
    uint32_t offset, total;
    struct psf_tag * output_tags = NULL;
    struct psf_tag * tag;
    DB_metaInfo_t *meta;
    double fval;
    
    deadbeef->pl_get_meta( it, ":URI", fname, sizeof(fname) );
    
    psf_version = psf_load( fname, &psf_file_system, 0, 0, 0, psf_info_meta, &state, 0, psf_error_log, 0 );
    
    if ( psf_version < 0 )
        goto error;
    
    snprintf (tmppath, sizeof (tmppath), "%s.temp", fname);
    fp = deadbeef->fopen (fname);
    if (!fp) {
        trace ("file not found %s\n", fname);
        goto error;
    }
    
    if (stat(fname, &stat_struct) != 0) {
        stat_struct.st_mode = 00640;
    }
    out = open (tmppath, O_CREAT | O_LARGEFILE | O_WRONLY, stat_struct.st_mode);
    trace ("will write tags into %s\n", tmppath);
    if (out < 0) {
        fprintf (stderr, "psf_write_metadata: failed to open temp file %s\n", tmppath);
        goto error;
    }
    
    buffer = (char *) malloc(16384);
    if (!buffer)
        goto error;
    
    deadbeef->fseek(fp, 4, SEEK_SET);
    deadbeef->fread(buffer, 8, 1, fp);
    
    reserved_size = get_le32(buffer + 0);
    exe_compressed_size = get_le32(buffer + 4);
    
    deadbeef->rewind(fp);
    
    offset = 0;
    total = reserved_size + exe_compressed_size + 16;
    
    while (offset < total)
    {
        uint32_t to_read = total - offset;
        if (to_read > 16384) to_read = 16384;
        deadbeef->fread(buffer, 1, to_read, fp);
        write(out, buffer, to_read);
    }
    
    strcpy(buffer, "[TAG]utf8=1\n");
    write(out, buffer, strlen(buffer));
    
    tag = state.tags;
    
    while (tag) {
        if (tag->name[0] == '_')
            output_tags = add_tag(output_tags, tag->name, tag->value);
        tag = tag->next;
    }

    fval = deadbeef->pl_get_item_replaygain(it, DDB_REPLAYGAIN_ALBUMGAIN);
    if (fval)
    {
        format_float(buffer, fval, " dB");
        output_tags = add_tag(output_tags, "replaygain_album_gain", buffer);
    }
    fval = deadbeef->pl_get_item_replaygain(it, DDB_REPLAYGAIN_ALBUMPEAK);
    if (fval)
    {
        format_float(buffer, fval, 0);
        output_tags = add_tag(output_tags, "replaygain_album_peak", buffer);
    }
    fval = deadbeef->pl_get_item_replaygain(it, DDB_REPLAYGAIN_TRACKGAIN);
    if (fval)
    {
        format_float(buffer, fval, " dB");
        output_tags = add_tag(output_tags, "replaygain_track_gain", buffer);
    }
    fval = deadbeef->pl_get_item_replaygain(it, DDB_REPLAYGAIN_TRACKPEAK);
    if (fval)
    {
        format_float(buffer, fval, 0);
        output_tags = add_tag(output_tags, "replaygain_track_peak", buffer);
    }
    
    meta = deadbeef->pl_get_metadata_head (it);
    while (meta) {
        if (strchr (":!_", meta->key[0])) {
            break;
        }
        if (meta->value && *meta->value) {
            output_tags = add_tag(output_tags, meta->key, meta->value);
        }
        meta = meta->next;
    }
    
    tag = output_tags;
    while (tag) {
        format_tag(buffer, tag->name, tag->value);
        write(out, buffer, strlen(buffer));
        tag = tag->next;
    }

    err = 0;
error:
    if (fp) {
        deadbeef->fclose (fp);
    }
    if (out) {
        close (out);
        out = -1;
    }
    if (buffer) {
        free (buffer);
    }
    if (!err) {
        deadbeef->pl_lock ();
        rename (tmppath, fname);
        deadbeef->pl_unlock ();
    }
    else {
        unlink (tmppath);
    }
    return err;
}

static void GSFLogger(struct mLogger* logger, int category, enum mLogLevel level, const char* format, va_list args)
{
    (void)logger;
    (void)category;
    (void)level;
    (void)format;
    (void)args;
}

static struct mLogger gsf_logger = {
    .log = GSFLogger,
};

int
psf_start (void) {
    bios_set_image( hebios, HEBIOS_SIZE );
    psx_init();
    sega_init();
    qsound_init();
    mLogSetDefaultLogger(&gsf_logger);
    
    conf_play_forever = deadbeef->conf_get_int ("playback.loop", PLAYBACK_MODE_LOOP_ALL) == PLAYBACK_MODE_LOOP_SINGLE;
    
    return 0;
}

int
psf_stop (void) {
    return 0;
}

int
psf_message (uint32_t id, uintptr_t ctx, uint32_t p1, uint32_t p2) {
    switch (id) {
    case DB_EV_CONFIGCHANGED:
        conf_play_forever = deadbeef->conf_get_int ("playback.loop", PLAYBACK_MODE_LOOP_ALL) == PLAYBACK_MODE_LOOP_SINGLE;
        break;
    }
    return 0;
}

extern "C"
__attribute__ ((visibility ("default")))
DB_plugin_t *
xsf_load (DB_functions_t *api) {
    deadbeef = api;
    return DB_PLUGIN (&xsf_plugin);
}

static const char *exts[] = { "psf", "minipsf", "psf2", "minipsf2", "ssf", "minissf", "dsf", "minidsf", "qsf", "miniqsf", "usf", "miniusf", "gsf", "minigsf", "2sf", "mini2sf", NULL };

// define plugin interface
DB_decoder_t xsf_plugin = {
    .plugin = { .type = DB_PLUGIN_DECODER,
                .api_vmajor = 1,
                .api_vminor = 0,
                .version_major = 1,
                .version_minor = 0,
                .id = "xsf",
                .name = "Highly Complete xSF player",
                .descr = "xSF player based on Neill Corlett's Highly Experimental,\n"
                         "Highly Theoretical, Highly Quixotic, and other authors'\n"
                         "mGBA, vio2sf, and lazyusf2.",
                .copyright = 
        "Copyright (C) 2003-2019 Christopher Snowhill <kode54@gmail.com>\n"
        "Copyright (C) 2003-2012 Neill Corlett <neill@neillcorlett.com>\n"
        "\n"
        "This program is free software; you can redistribute it and/or\n"
        "modify it under the terms of the GNU General Public License\n"
        "as published by the Free Software Foundation; either version 2\n"
        "of the License, or (at your option) any later version.\n"
        "\n"
        "This program is distributed in the hope that it will be useful,\n"
        "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
        "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
        "GNU General Public License for more details.\n"
        "\n"
        "You should have received a copy of the GNU General Public License\n"
        "along with this program; if not, write to the Free Software\n"
        "Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.\n"
    ,
                .website = "http://kode54.net",
                .start = psf_start,
                .stop = psf_stop,
                .message = psf_message,
    },
    .open = psf_open,
    .init = psf_init,
    .free = psf_free,
    .read = psf_read,
    .seek = psf_seek,
    .seek_sample = psf_seek_sample,
    .insert = psf_insert,
    .read_metadata = psf_read_metadata,
    .write_metadata = psf_write_metadata,
    .exts = exts,
};
