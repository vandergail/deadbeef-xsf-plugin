PLUGIN = xsf.so

CFLAGS = -O2 -fPIC -c
LDFLAGS = -fPIC -shared /usr/lib/libmgba.so.0.8 -lz

PSFLIB_OBJS    = psflib/psflib.o psflib/psf2fs.o

PSFLIB_LIB     = libpsflib.a

HE_DIR         = Highly_Experimental/Core

HE_OBJS        = $(HE_DIR)/bios.o $(HE_DIR)/iop.o $(HE_DIR)/ioptimer.o \
                 $(HE_DIR)/psx.o $(HE_DIR)/r3000.o $(HE_DIR)/spucore.o \
                 $(HE_DIR)/spu.o $(HE_DIR)/vfs.o

HE_LIB         = libhe.a

HT_DIR         = Highly_Theoretical/Core

HT_OBJS        = $(HT_DIR)/arm.o $(HT_DIR)/dcsound.o $(HT_DIR)/satsound.o \
                 $(HT_DIR)/sega.o $(HT_DIR)/yam.o $(HT_DIR)/m68k/m68kcpu.o \
                 $(HT_DIR)/m68k/m68kops.o

HT_LIB         = libht.a

HQ_DIR         = Highly_Quixotic/Core

HQ_OBJS        = $(HQ_DIR)/kabuki.o $(HQ_DIR)/qmix.o $(HQ_DIR)/qsound.o \
                 $(HQ_DIR)/qsound_ctr.o $(HQ_DIR)/z80.o

HQ_LIB         = libhq.a

LAZYUSF_LIB    = lazyusf2/liblazyusf.a

VIO2SF_DIR     = vio2sf/src/vio2sf/desmume

VIO2SF_OBJS    = $(VIO2SF_DIR)/FIFO.o $(VIO2SF_DIR)/GPU.o $(VIO2SF_DIR)/MMU.o \
                 $(VIO2SF_DIR)/NDSSystem.o $(VIO2SF_DIR)/SPU.o \
                 $(VIO2SF_DIR)/arm_instructions.o $(VIO2SF_DIR)/armcpu.o \
                 $(VIO2SF_DIR)/barray.o $(VIO2SF_DIR)/bios.o \
                 $(VIO2SF_DIR)/cp15.o $(VIO2SF_DIR)/isqrt.o \
                 $(VIO2SF_DIR)/matrix.o $(VIO2SF_DIR)/mc.o \
                 $(VIO2SF_DIR)/resampler.o $(VIO2SF_DIR)/state.o \
                 $(VIO2SF_DIR)/thumb_instructions.o

VIO2SF_LIB     = libvio2sf.a

OBJS           = cxsf.o

.PHONY: all clean

all: $(PLUGIN)

$(PSFLIB_LIB) : $(PSFLIB_OBJS)
	$(AR) rcs $@ $^

$(HE_LIB) : $(HE_OBJS)
	$(AR) rcs $@ $^

$(HT_LIB) : $(HT_OBJS)
	$(AR) rcs $@ $^

$(HQ_LIB) : $(HQ_OBJS)
	$(AR) rcs $@ $^

$(VIO2SF_LIB) : $(VIO2SF_OBJS)
	$(AR) rcs $@ $^

cxsf.o: cxsf.cpp
	$(CXX) $(CFLAGS) -DEMU_COMPILE -DEMU_LITTLE_ENDIAN -ImGBA/include $< -o $@

$(HE_DIR)/%.o: $(HE_DIR)/%.c
	$(CC) $(CFLAGS) -DEMU_COMPILE -DEMU_LITTLE_ENDIAN $< -o $@

$(HT_DIR)/%.o: $(HT_DIR)/%.c
	$(CC) $(CFLAGS) -DEMU_COMPILE -DEMU_LITTLE_ENDIAN -DHAVE_STDINT_H -DUSE_M68K -DLSB_FIRST $< -o $@

$(HQ_DIR)/%.o: $(HQ_DIR)/%.c
	$(CC) $(CFLAGS) -DEMU_COMPILE -DEMU_LITTLE_ENDIAN $< -o $@

$(LAZYUSF_LIB): lazyusf2/Makefile
	$(MAKE) -C lazyusf2 liblazyusf.a

.c.o:
	$(CC) $(CFLAGS) -o $@ $*.c

.cpp.o:
	$(CXX) $(CFLAGS) -o $@ $*.cpp

$(PLUGIN): $(OBJS) $(PSFLIB_LIB) $(HE_LIB) $(HT_LIB) $(HQ_LIB) $(LAZYUSF_LIB) $(VIO2SF_LIB)
	$(CXX) -o $@ $(OBJS) $(PSFLIB_LIB) $(HE_LIB) $(HT_LIB) $(HQ_LIB) $(LAZYUSF_LIB) $(VIO2SF_LIB) $(LDFLAGS)

clean:
	rm -f $(PSFLIB_LIB) $(PSFLIB_OBJS) $(HE_LIB) $(HE_OBJS) $(HT_LIB) $(HT_OBJS) $(HQ_LIB) $(HQ_OBJS) $(VIO2SF_LIB) $(VIO2SF_OBJS) $(OBJS) $(PLUGIN) > /dev/null
	$(MAKE) -C lazyusf2 clean
