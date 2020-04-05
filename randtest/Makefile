CFLAGS = -std=gnu99 -Os -Wall -Wextra
CPPFLAGS = -I..
LDLIBS = -lssl -lcrypto

all: randtest

randtest: ../botched_rand_32.o randtest.o

clean:
	$(RM) randtest randtest.o

