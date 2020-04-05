CPPFLAGS = -MMD
CFLAGS = -std=gnu99 -Os -Wall -Wextra
LDLIBS = -lssl -lcrypto

test_objects = botched_rand_32.o test.o

all: vendor tool

-include $(test_objects:.o=.d)

tool: test

test: $(test_objects)
#	$(CC) -o $@ $^

vendor:
	$(MAKE) -C $@

clean:
	$(RM) $(test_objects) $(test_objects:.o=.d)
	$(RM) test
	$(MAKE) -C vendor clean

.PHONY: vendor
