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

void println_buf(unsigned char *buf, int len) {
	for (int i = 0; i < len; i++) {
		printf("%02x%s", buf[i], (i % 4) == 3 ? " " : "");
	}
	printf("\n");
}

void i386_b_rand_reset(pid_t pid);
int i386_ssleay_rand_bytes(unsigned char *buf, int num);

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
}
