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

static bool checkDir(string &rootDir);

static int opt_check_count = 5; // TODO use
static bool opt_decrypt_files = false; // TODO use
static bool opt_first_only = true;

auto ctx = std::make_shared<EncFS_Context>();

static void show_version() {
	cerr << autosprintf("findvolkey version %s", FVK_VERSION) << "\n";
}

static void usage(const char *name) {
	cerr
		<< "Usage:\n"
		<< "\n"
		<< autosprintf("  %s (root dir) search-vuln [--full-search] [--check-count=n] [--check-contents]\n", name)
		<< "      to search for vulnerable keys and list candidates\n"
		<< autosprintf("  %s (root dir) test-key [--check-count=n] [--check-contents] (key-id)\n", name)
		<< "      to test a specific key\n"
		<< autosprintf("  %s (root dir) write-key (key-id)\n", name)
		<< "      to write a new config file with the given volume key\n"
		<< autosprintf("  %s (root dir) dump-key\n", name)
		<< "      to decrypt a volume using password and dump the raw key bytes\n"
		<< "\n"
		<< "(root dir) is the path to the encrypted encfs volume\n"
		<< "(key-id) describes the volume key, can be a hex sequence (e.g. raw ab cd ef 01 23 ...) or generator+params as output by search-vuln (e.g. esd i386 4 1234)\n";
}


// from encfs/FileUtils.cpp, am too lazy to patch it to expose it
struct ConfigInfo_ {
  const char *fileName;
  ConfigType type;
  const char *environmentOverride;
} ConfigFileMapping[] = {
    // current format
    {".encfs6.xml", Config_V6, "ENCFS6_CONFIG"},
    // backward compatible support for older versions
    {".encfs5", Config_V5, "ENCFS5_CONFIG"},
    {".encfs4", Config_V4, nullptr},
    {nullptr, Config_None, nullptr}};

static int writeNewVolumeKey(bool useStdin, string &rootDir, unsigned char *keybytes, int keylen) {
	if (!checkDir(rootDir)) return EXIT_FAILURE;

	EncFSConfig *config = new EncFSConfig;
	ConfigType cfgType = readConfig(rootDir, config, "");

	if (cfgType == Config_None) {
		cout << _("Unable to load or parse config file\n");
		return EXIT_FAILURE;
	}

	// instanciate proper cipher
	std::shared_ptr<Cipher> cipher = Cipher::New(config->cipherIface, config->keySize);
	if (!cipher) {
		cout << autosprintf(_("Unable to find specified cipher \"%s\"\n"),
				config->cipherIface.name().c_str());
		return EXIT_FAILURE;
	}

	// create the volume key from the key bytes
	CipherKey volumeKey = cipher->forceKey(keybytes, keylen);

	// Now, get New user key..
	cout << _("Enter new Encfs password\n");
	// reinitialize salt and iteration count
	config->kdfIterations = 0;  // generate new

	CipherKey userKey;
	if (useStdin) {
		userKey = config->getUserKey(true);
	} else {
		userKey = config->getNewUserKey();
	}

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

		/* need to make backup of config file. For that we need to find
		 * out its path */
		string configPath;
		bool foundFilename = false;
		ConfigInfo_ *nm = ConfigFileMapping;
		for (; nm->fileName != nullptr; nm++) {
			if (!(nm->type == cfgType)) {
				continue;
			}

			configPath = rootDir + nm->fileName;
			foundFilename = true;
			break;
		}
		if (!foundFilename) {
			cerr << "Unable to determine path to config file, cannot make backup, aborting\n";
			exit(1);
		}

		// Construct backup path name
		time_t rawtime;
		struct tm *timeinfo;
		char buffer[64];
		time(&rawtime);
		timeinfo = localtime(&rawtime);
		strftime(buffer, 64, "%Y%m%d-%H%M%S", timeinfo);
		string backupName = configPath + '-' + buffer;

		// Make backup
		int cfg_fd = open(configPath.c_str(), O_RDONLY);
		if (cfg_fd == -1) {
			cerr << "Unable to open old config file " << configPath << " for reading:";
			perror("");
			exit(1);
		}
		int bup_fd = open(backupName.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
		if (bup_fd == -1) {
			cerr << "Unable to open backup config file " << backupName << " for writing:";
			perror("");
			exit(1);
		}
		while (1) {
			#define BLOCKSIZE 64
			char *buf[BLOCKSIZE];
			ssize_t nread = read(cfg_fd, buf, BLOCKSIZE);
			if (nread > 0) {
				ssize_t nwritten = write(bup_fd, buf, nread);
				if (nwritten != nread) {
					perror("Write to backup config file failed");
					exit(1);
				}
			} else if (nread == 0) {
				// done
				break;
			} else {
				perror("Read from original config file failed");
				exit(1);
			}
		}
		if (close(bup_fd) != 0) {
			perror("Closing backup config file failed");
			exit(1);
		}
		if (close(cfg_fd) != 0) {
			perror("Closing original config file failed");
			exit(1);
		}
		
		cerr << "Created backup of old config file under " << backupName << "\n";

		if (saveConfig(cfgType, rootDir, config, "")) {
			// password modified -- changes volume key of filesystem..
			cout << _("Volume Key successfully updated. You can now mount the volume as usual :-)\n");
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
		LOG(ERROR) << "Key expected, but no arguments given.";
		exit(EXIT_FAILURE);
	}

	if (!strcmp(args[0], "raw")) {
		if (nargs - 1 != nkeybytes) {
			LOG(ERROR) << "Expected " << nkeybytes << " bytes of key material but " << (nargs - 1) << " bytes have been provided as arguments";
			exit(EXIT_FAILURE);
		}
		for (int i = 0; i < nkeybytes; i++) {
			long cur = strtol(args[1+i], NULL, 16);
			out_buf[i] = cur & 0xff;
		}
	} else if (!strcmp(args[0], "esd")) {
		if (nargs != 4) {
			LOG(ERROR) << "Expected exactly three arguments (architecture, srand bytes, process id)";
			exit(EXIT_FAILURE);
		}

		Architecture arch;
		if (!strcmp(args[1], "i386")) {
			arch = Arch_i386;
		} else if (!strcmp(args[1], "amd64")) {
			arch = Arch_amd64;
		} else {
			LOG(ERROR) << "Unknown architecture \"" << args[1] << "\"";
			exit(EXIT_FAILURE);
		}
		long srandBytes = strtol(args[2], NULL, 10);
		long pid = strtol(args[3], NULL, 10);

		EncfsShaOnDebianKeygen keygen(arch, srandBytes);
		keygen.setPID(pid);
		keygen.generateKeybytes(out_buf, nkeybytes);
	} else {
		LOG(ERROR) << "Unknown key type \"" << args[0] << "\"";
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
		LOG(ERROR) << "Unable to open " << rootDir << " as an EncFS volume\n";
		return EXIT_FAILURE;
	}
	return computeCruftScore(rootPtr, "/", -3, +3);
}

static int testForVulnerableKeysOfDebian(EncfsShaOnDebianKeygen keygen, const string &rootDir, int keylen) {
	unsigned char *keybytes = (unsigned char*) alloca(keylen);
	int numcand = 0;

	string keygenDescr = keygen.describe();
	LOG(TRACE) << "checking keys of " << keygenDescr;
	for (int pid = 0; pid <= 32768; pid++) {
		keygen.setPID(pid);
		keygen.generateKeybytes(keybytes, keylen);
		int cruftScore = computeCruftScoreForRootdir(rootDir, keybytes, keylen);
		if (cruftScore >= 0) {
			cout << "Found candidate for volume key (score " << cruftScore << "): " << keygenDescr << ' ' << pid << "\n";
			numcand++;
			if (opt_first_only) {
				cout << "(not searching for additional keys. Use --full-search for that)\n";
				return numcand;
			}
		}
	}
	return numcand;
}


int main(int argc, char **argv) {
	START_EASYLOGGINGPP(argc, argv);
	//encfs::initLogging();
	el::Configurations defaultConf;
	defaultConf.setToDefault();
	defaultConf.set(el::Level::Global, el::ConfigurationType::ToFile, "false");
	el::Loggers::addFlag(el::LoggingFlag::ColoredTerminalOutput);
	defaultConf.setGlobally(el::ConfigurationType::Format, "%level %msg");
	el::Loggers::reconfigureLogger("default", defaultConf);

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
		{"full-search",    no_argument,        nullptr, 'f'},
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
		case 'f':
			opt_first_only = false;
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
		LOG(ERROR) << "Missing arguments. At least two non-option arguments (rootdir and command) required, but only " << argc << " given";
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
		LOG(ERROR) << rootDir << " does not seem to be an EncFS volume";
		return EXIT_FAILURE;
	case Config_Prehistoric:
	case Config_V3:
		LOG(ERROR) << rootDir << " contains an unsupported (very old) EncFS volume";
		return EXIT_FAILURE;
	case Config_V4:
	case Config_V5:
	case Config_V6:
		break;
	default:
		LOG(ERROR) << "Unexpected EncFS config type";
		return EXIT_FAILURE;
	}

	LOG(INFO) << "Opened EncFS volume " << rootDir;
	showFSInfo(config.get());
	std::shared_ptr<SSL_Cipher> cipher = dynamic_pointer_cast<SSL_Cipher>(config.get()->getCipher());
	cerr << "Number of key bytes: " << cipher->rawKeySize() << "\n\n";

	// Note that for key verification and re-writing we need to call initFS again, but this way we got at least key parameters

	// If the volume was created without filename encrytion then we MUST turn on content verification
	if (config.get()->nameIface.name() == "nameio/null") {
		LOG(WARNING) << "setting --decrypt-files because the volume has unencrypted filenames and verification is not possible otherwise";
		opt_decrypt_files = true;
	}

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
			LOG(ERROR) << "Unable to open " << rootDir << " as an EncFS volume";
			return EXIT_FAILURE;
		}

		unsigned char *keydata = SSLKey_getData((SSLKey*)(rootPtr->volumeKey.get()));
		int keylen = cipher->rawKeySize();

		printf("raw ");
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
			LOG(ERROR) << "Unable to open " << rootDir << " as an EncFS volume\n";
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
				if (opt_first_only && numcand > 0) break;
				EncfsShaOnDebianKeygen kg(arch, srandBytes);
				numcand += testForVulnerableKeysOfDebian(kg, rootDir, keylen);
			}
		}
		if (numcand > 0) {
			cout << "Some key candidates were found :-D To write a key, do:\n";
			cout << "  findvolkey " << rootDir << " write-key esd ...\n";
			return EXIT_SUCCESS;
		} else {
			cout << "No candidate keys found. :-(\n";
			cout << "Possible reasons:\n";
			cout << "- The volume was not initially created using a vulnerable OpenSSL version\n";
			cout << "- The tested key generation algorithms do not match that of the version used to create the volume (\"" << config.get()->creator << "\")\n";
			return EXIT_FAILURE;
		}
	} else if (!strcmp(command, "write-key")) {
		int keylen = cipher->rawKeySize();
		unsigned char *keybytes = (unsigned char*) malloc(keylen);
		parseKeyFromArgs(argv+2, argc-2, keybytes, keylen);
		return writeNewVolumeKey(false, rootDir, keybytes, keylen);
	} else {
		LOG(ERROR) << "Unknown command: " << command;
		return EXIT_FAILURE;
	}
}
