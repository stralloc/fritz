# set this to yes or no to build with libsodium or subnacl
WITH_LIBSODIUM=no

GCC=mingw32-gcc.exe
WINDRES=windres.exe

ifeq ($(WITH_LIBSODIUM),yes)
CFLAGS=-Os -DWITH_LIBSODIUM=1 -I. -I..\sodium\include  -fno-stack-protector -fstack-protector-all -Wstack-protector
LDDFLAGS=-L. -L..\sodium\lib -lsodium -lgdi32 -lcrypt32 -mwindows -static
else
CFLAGS=-Os -I. -I..\subnacl\include  -fno-stack-protector -fstack-protector-all -Wstack-protector
LDDFLAGS=-L. -L..\subnacl -lnacl -lgdi32 -lcrypt32 -mwindows -static
endif

BIN=fritz.exe
EN_BIN=fritz[en].exe
STRIP_ARGS=-R .note -R .comment -R .gnu.version
OBJ=fritz.o base64.o stralloc.o selftests.o

${BIN}: Makefile gui.rc fritz.c stralloc.c selftests.c german.h english.h
	${WINDRES} -i gui.rc -o gui.o
	${GCC} ${CFLAGS} -include german.h fritz.c -c
	${GCC} ${CFLAGS} base64.c -c
	${GCC} ${CFLAGS} stralloc.c -c
	${GCC} ${CFLAGS} selftests.c -c
	${GCC} ${CFLAGS} fritz.o gui.o base64.o stralloc.o selftests.o -o ${BIN} ${LDDFLAGS}
	strip ${STRIP_ARGS} ${BIN}
	${GCC} ${CFLAGS} -include english.h fritz.c -c
	${GCC} ${CFLAGS} fritz.o gui.o base64.o stralloc.o selftests.o -o ${EN_BIN} ${LDDFLAGS}
	strip ${STRIP_ARGS} ${EN_BIN}
	
all: gui.o ${BIN}

clean:
	del ${OBJ} ${BIN} ${EN_BIN} gui.o