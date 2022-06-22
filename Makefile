MKPROF=
#MKPROF=time
CC=cc
CFLAGS=-std=c99 -O2 -pedantic -Wdeprecated -Wall -Wno-unused-function -Werror
#CFLAGS=-std=c99 -O0 -g -pedantic -Wdeprecated -Wall -Wno-unused-function \
#    -Werror
DS=ds
#DS=ds_malloc
.if $(DS) == 'ds'
MUXFS_DS=1
.else
MUXFS_DS=0
.endif
OBJ=chk.o \
    conf.o \
    desc.o \
    dev.o \
    $(DS).o \
    state.o \
    util.o \
    version.o

all: unity
#all: incremental

incremental: mount_muxfs_incremental newfs_muxfs_incremental

unity: mount_muxfs_unity newfs_muxfs_unity

gen: ds.h gen.c chk.h mount_muxfs.h
	${MKPROF} ${CC} ${CFLAGS} \
	   -I. \
	   -DMUXFS= \
	   -DMUXFS_DEC=extern \
	   -o gen \
	   gen.c

gen.h: gen
	${MKPROF} ./gen >gen.h

.SUFFIXES: .c .o
.c.o: ds.h gen.h muxfs.h mount_muxfs.h
	${MKPROF} ${CC} ${CFLAGS} \
	   -I. \
	   -DMUXFS= \
	   -DMUXFS_DEC=extern \
	   -c \
	   -o $@  $<

mount_muxfs_incremental: ds.h gen.h muxfs.h mount_muxfs.h ops.o ${OBJ}
	${MKPROF} ${CC} ${CFLAGS} \
	   -I. \
	   -DMUXFS= \
	   -DMUXFS_DEC=extern \
	   -lfuse -lz \
	   -o mount_muxfs \
	   mount_muxfs.c \
	   ops.o \
	   ${OBJ}

newfs_muxfs_incremental: ds.h gen.h muxfs.h ${OBJ}
	${MKPROF} ${CC} ${CFLAGS} \
	   -I. \
	   -DMUXFS= \
	   -DMUXFS_DEC=extern \
	   -lz \
	   -o newfs_muxfs \
	   newfs_muxfs.c \
	   ${OBJ}

gen_h_unity:
	${MKPROF} echo \
	   '/* gen.h contents not needed for unity build. */' \
	   >gen.h

mount_muxfs_unity: gen_h_unity
	${MKPROF} ${CC} ${CFLAGS} \
	   -I. \
	   -DMUXFS=static \
	   -DMUXFS_DEC=static \
	   -DMUXFS_DS=$(MUXFS_DS) \
	   -Dmuxfs_chk=muxfs_chk_p \
	   -lfuse -lz \
	   -o mount_muxfs \
	   mount_muxfs_unity.c

newfs_muxfs_unity: gen_h_unity
	${MKPROF} ${CC} ${CFLAGS} \
	   -I. \
	   -DMUXFS=static \
	   -DMUXFS_DEC=static \
	   -DMUXFS_DS=$(MUXFS_DS) \
	   -Dmuxfs_chk=muxfs_chk_p \
	   -lz \
	   -o newfs_muxfs \
	   newfs_muxfs_unity.c

install:
	install -m 0555 mount_muxfs /usr/local/sbin/mount_muxfs
	install -m 0555 newfs_muxfs /usr/local/sbin/newfs_muxfs

clean:
	rm ds.o ds_malloc.o ops.o ${OBJ} mount_muxfs newfs_muxfs gen.h gen \
	   >/dev/null 2>&1 || true
