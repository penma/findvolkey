# Quickly hacked together

DEFS = -DPACKAGE=\"encfs\" -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=29 -DELPP_DISABLE_DEFAULT_CRASH_HANDLING -DELPP_NO_DEFAULT_LOG_FILE -DELPP_SYSLOG -DELPP_CUSTOM_COUT=std::cerr -DHAVE_DIRENT_D_TYPE=1 -DVERSION=\"1.9.5-32-g3d4ef00\"
CPPFLAGS = $(DEFS) -I../vendor

encfs_objs = autosprintf.o base64.o BlockFileIO.o BlockNameIO.o Cipher.o CipherFileIO.o CipherKey.o ConfigReader.o ConfigVar.o Context.o DirNode.o encfs.o encfsctl.o Error.o FileIO.o FileNode.o FileUtils.o Interface.o MACFileIO.o main.o makeKey.o MemoryPool.o NameIO.o NullCipher.o NullNameIO.o openssl.o RawFileIO.o readpassphrase.o SSL_Cipher.o StreamNameIO.o test.o XmlReader.o

all: $(encfs_objs)

clean:
	$(RM) $(encfs_objs)
