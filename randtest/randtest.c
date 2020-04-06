#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "botched_rand.h"
BOTCHED_RAND_FUNCS(i386_);

// from SSL_Cipher.cpp
int BytesToKey(int keyLen, int ivLen, EVP_MD *md, unsigned char *data, int dataLen, unsigned int rounds, unsigned char *out_keyiv) {
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
    int toCopy = nkeyiv < mds - offset ? nkeyiv : mds - offset;
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

void println_buf(unsigned char *buf, int len) {
	for (int i = 0; i < len; i++) {
		printf("%02x%s", buf[i], (i % 4) == 3 ? " " : "");
	}
	printf("\n");
}

static void botched_rand(unsigned char *buf, int len, pid_t pid) {
	i386_b_rand_reset(pid);
	i386_ssleay_rand_bytes(buf, len);
}


int main() {
	printf("Our PID as seen by OpenSSL is: %d\n", getpid());
	printf("RAND_status is %d\n", RAND_status());

	int len = 32;
	unsigned char buf[len];
	int res_rand = RAND_bytes(buf, len);
	if (!res_rand) {
		printf("Error doing RAND_bytes: %lu\n", ERR_get_error());
		exit(1);
	}

	printf("Buffer: ");
	println_buf(buf, len);

	// Try again
	res_rand = RAND_bytes(buf, len);
	if (!res_rand) {
		printf("Error doing RAND_bytes: %lu\n", ERR_get_error());
		exit(1);
	}

	printf("Second: ");
	println_buf(buf, len);

	// Now try to replicate first invocation of the broken OpenSSL RNG
	botched_rand(buf, len, getpid());
	printf("Replica ");
	println_buf(buf, len);

	botched_rand(buf, len, getpid());
	printf("Repli_2 ");
	println_buf(buf, len);
	i386_ssleay_rand_bytes(buf, len);
	printf("Repli_' ");
	println_buf(buf, len);

	printf("\n");
	i386_b_rand_reset(18625);
	i386_ssleay_rand_bytes(buf, 4); // some versions did this
	i386_ssleay_rand_bytes(buf, len);
	println_buf(buf, len);
	// but those were not used directly as key bytes
	unsigned char kbuf[48];
	int bytes = BytesToKey(32, 16, EVP_sha1(), buf, len, 16, kbuf);
	println_buf(kbuf, 48);
}
