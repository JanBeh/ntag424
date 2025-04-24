# BSD Makefile, use bmake on Linux

LIBNFC_INCDIR ?= /usr/local/include
LIBNFC_LIBDIR ?= /usr/local/lib

all: .PHONY \
  libntag424.a lrp-test ntag424-test ntag424-util ntag424-enable-lrp

aes.o: aes.c
	cc -Wall -O2 -c -fPIC aes.c

lrp.o: lrp.h lrp.c
	cc -Wall -O2 -c -fPIC lrp.c

ntag424.o: ntag424.h ntag424.c
	cc -Wall -O2 -c -fPIC ntag424.c

libntag424.a: ntag424.o lrp.o aes.o
	rm -f libntag424.a
	ar rcs libntag424.a ntag424.o lrp.o aes.o

lrp-test: lrp-test.c lrp.c lrp.h aes.o
	cc -Wall -g -O2 -o lrp-test lrp-test.c aes.o

ntag424-test: ntag424-test.c ntag424.h libntag424.a
	cc -Wall -g -O2 \
	  -I$(LIBNFC_INCDIR) -L$(LIBNFC_LIBDIR) \
	  -o ntag424-test ntag424-test.c libntag424.a -lnfc

ntag424-util: ntag424-util.c ntag424.h libntag424.a
	cc -Wall -g -O2 \
	  -I$(LIBNFC_INCDIR) -L$(LIBNFC_LIBDIR) \
	  -o ntag424-util ntag424-util.c libntag424.a -lnfc

ntag424-enable-lrp: ntag424-enable-lrp.c aes.h aes.o
	cc -Wall -O2 \
	  -I$(LIBNFC_INCDIR) -L$(LIBNFC_LIBDIR) \
	  -o ntag424-enable-lrp ntag424-enable-lrp.c aes.o -lnfc

test: lrp-test
	./lrp-test

clean: .PHONY
	rm -f *.o lib*.a \
	  lrp-test ntag424-test ntag424-util ntag424-enable-lrp
