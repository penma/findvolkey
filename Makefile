CPPFLAGS = -MMD
CFLAGS = -std=gnu99 -Os -Wall -Wextra
CXXFLAGS = -Os -Wall -Wextra

DEFS = -DPACKAGE=\"encfs\" -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=29 -DHAVE_DIRENT_D_TYPE=1 -DVERSION=\"1.9.5-32-g3d4ef00\" -DFVK_VERSION=\"0.1\"
CPPFLAGS += $(DEFS) -Ivendor -Iencfs

LDFLAGS = -Lencfs
LDLIBS = -lssl -lcrypto -lencfs -lfuse

fvk_objects = botched_rand_32.o botched_rand_64.o findvolkey.o

all: vendor encfs randtest findvolkey

-include $(fvk_objects:.o=.d)

findvolkey: $(fvk_objects) vendor/easylogging++.o vendor/tinyxml2.o
	$(CXX) -o $@ $^ $(LDFLAGS) $(LDLIBS)

vendor encfs randtest:
	$(MAKE) -C $@

clean:
	$(RM) $(fvk_objects) $(fvk_objects:.o=.d) findvolkey
	$(MAKE) -C vendor clean
	$(MAKE) -C randtest clean
	$(MAKE) -C encfs clean

.PHONY: randtest vendor encfs
