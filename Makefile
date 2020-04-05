CPPFLAGS = -MMD
CFLAGS = -std=gnu99 -Os -Wall -Wextra
LDLIBS = -lssl -lcrypto

brand_objects = botched_rand_32.o

all: botched_rand_32.o vendor randtest

-include $(brand_objects:.o=.d)

vendor randtest:
	$(MAKE) -C $@

clean:
	$(RM) $(brand_objects) $(brand_objects:.o=.d)
	$(MAKE) -C vendor clean
	$(MAKE) -C randtest clean

.PHONY: randtest vendor
