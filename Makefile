all: unity
#all: incremental

COMMON_CFLAGS=-std=c99 -pedantic -Wdeprecated -Wall -Wno-unused-function \
    -Werror
CFLAGS=$(COMMON_CFLAGS) -O2 -DNDEBUG=1
#CFLAGS=$(COMMON_CFLAGS) -O0 -g
#CFLAGS=$(COMMON_CFLAGS) -O0 -g -pg -static
CC=cc

MKPROF=
#MKPROF=time

MUXFS_DS_MALLOC=0
.if $(MUXFS_DS_MALLOC)
DS=ds_malloc
.else
DS=ds
.endif

OBJ=chk.o \
    conf.o \
    desc.o \
    dev.o \
    $(DS).o \
    format.o \
    lfile.o \
    mount.o \
    muxfs.o \
    ops.o \
    scan.o \
    state.o \
    sync.o \
    util.o \
    version.o

incremental: muxfs_incremental

unity: muxfs_unity

gen: ds.h gen.c chk.h
	${MKPROF} ${CC} ${COMMON_CFLAGS} \
	    -I. \
	    -DMUXFS= \
	    -DMUXFS_DEC=extern \
	    -o gen \
	    gen.c

gen.h: gen
	${MKPROF} ./gen >gen.h

.SUFFIXES: .c .o
.c.o: ds.h gen.h muxfs.h
	${MKPROF} ${CC} ${CFLAGS} \
	    -I. \
	    -DMUXFS= \
	    -DMUXFS_DEC=extern \
	    -c \
	    -o $@  $<

muxfs_incremental: ds.h gen.h muxfs.h ${OBJ}
	${MKPROF} ${CC} ${CFLAGS} \
	    -I. \
	    -DMUXFS= \
	    -DMUXFS_DEC=extern \
	    -lfuse -lz \
	    -o muxfs \
	    ${OBJ}

gen_h_unity:
	${MKPROF} echo \
	    '/* gen.h contents not needed for unity build. */' \
	    >gen.h

muxfs_unity: gen_h_unity
	${MKPROF} ${CC} ${CFLAGS} \
	    -I. \
	    -DMUXFS=static \
	    -DMUXFS_DEC=static \
	    -DMUXFS_DS_MALLOC=$(MUXFS_DS_MALLOC) \
	    -Dmuxfs_chk=muxfs_chk_p \
	    -lfuse -lz \
	    -o muxfs \
	    unity.c

install:
	install -o root -g bin -m 0755 muxfs	/usr/local/sbin/muxfs
	install -o root -g bin -m 0644 muxfs.1	/usr/local/man/man1/muxfs.1

clean:
	rm ds.o ds_malloc.o ${OBJ} \
	    muxfs \
	    gen.h gen \
	    >/dev/null 2>&1 || true
