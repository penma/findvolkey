/*
 * #define s expected by this code:
 * - OLD_SSL: define this if the code is supposed to run on some unspecified older version of OpenSSL (without EVP_MD_CTX_new)
 * - PLATFORM_LONG: type of "long" of the architecture under attack
 * - PLATFORM_UNSIGNED_LONG: same, but for "unsigned long"
 * - FUNC_PREFIX: prefix for the names of exported functions, e.g. deb32_
 * e.g. if the key to be recovered was generated on x86 then use (u)int32_t here
 */

#if !defined(PLATFORM_LONG) || !defined(PLATFORM_UNSIGNED_LONG)
#error "This file needs to be included with PLATFORM_LONG and PLATFORM_UNSIGNED_LONG defined"
#endif
#if !defined(FUNC_PREFIX)
#error "This file needs to be included with FUNC_PREFIX defined"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "host_flags.h"

#define CONCAT_NAME(n1,n2) n1##n2
#define PFX_EVAL(n1,n2) CONCAT_NAME(n1,n2)
#define PREFIXED_NAME(name) PFX_EVAL(FUNC_PREFIX,name)

typedef PLATFORM_LONG orig_long;
typedef PLATFORM_UNSIGNED_LONG orig_unsigned_long;

#define ENTROPY_NEEDED 32  /* require 256 bits = 32 bytes of randomness */

#define MD_Update(a,b,c)        EVP_DigestUpdate(a,b,c)
#define MD_Final(a,b)           EVP_DigestFinal_ex(a,b,NULL)
// SHA
#define MD_DIGEST_LENGTH        SHA_DIGEST_LENGTH
#define MD_Init(a)              EVP_DigestInit_ex(a,EVP_sha1(), NULL)
#define MD(a,b,c)               EVP_Digest(a,b,c,NULL,EVP_sha1(), NULL)

#define STATE_SIZE	1023
static int state_num=0,state_index=0;
static unsigned char state[STATE_SIZE+MD_DIGEST_LENGTH];
static unsigned char md[MD_DIGEST_LENGTH];
static orig_long md_count[2]={0,0};
static double entropy=0;
static int initialized=0;

static int stirred_pool = 0;

static pid_t fake_pid;

void PREFIXED_NAME(b_rand_reset)(pid_t pid) {
	state_num = state_index = 0;
	memset(state, 0, sizeof(state));
	memset(md, 0, sizeof(md));
	md_count[0] = md_count[1] = 0;
	entropy = 0;
	initialized = 0;

	stirred_pool = 0;

	fake_pid = pid;
}

#ifdef OLD_SSL
static EVP_MD_CTX *EVP_MD_CTX_new(void) { return calloc(sizeof(EVP_MD_CTX), 1); }
static void EVP_MD_CTX_free(EVP_MD_CTX *ctx) { free(ctx); }
#else // !OLD_SSL
static int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx) { EVP_MD_CTX_reset(ctx); }
#endif

static void ssleay_rand_add(const void *buf, int num, double add)
{
	int i,j,k,st_idx;
	orig_long md_c[2];
	unsigned char local_md[MD_DIGEST_LENGTH];
	EVP_MD_CTX *m;

	/*
	 * (Based on the rand(3) manpage)
	 *
	 * The input is chopped up into units of 20 bytes (or less for
	 * the last block).  Each of these blocks is run through the hash
	 * function as follows:  The data passed to the hash function
	 * is the current 'md', the same number of bytes from the 'state'
	 * (the location determined by in incremented looping index) as
	 * the current 'block', the new key data 'block', and 'count'
	 * (which is incremented after each use).
	 * The result of this is kept in 'md' and also xored into the
	 * 'state' at the same locations that were used as input into the
         * hash function.
	 */

	/* check if we already have the lock */
	st_idx=state_index;

	/* use our own copies of the counters so that even
	 * if a concurrent thread seeds with exactly the
	 * same data and uses the same subarray there's _some_
	 * difference */
	md_c[0] = md_count[0];
	md_c[1] = md_count[1];

	memcpy(local_md, md, sizeof md);

	/* state_index <= state_num <= STATE_SIZE */
	state_index += num;
	if (state_index >= STATE_SIZE)
	{
		state_index%=STATE_SIZE;
		state_num=STATE_SIZE;
	}
	else if (state_num < STATE_SIZE)	
	{
		if (state_index > state_num)
			state_num=state_index;
	}
	/* state_index <= state_num <= STATE_SIZE */

	/* state[st_idx], ..., state[(st_idx + num - 1) % STATE_SIZE]
	 * are what we will use now, but other threads may use them
	 * as well */

	md_count[1] += (num / MD_DIGEST_LENGTH) + (num % MD_DIGEST_LENGTH > 0);

	m = EVP_MD_CTX_new();
	EVP_MD_CTX_init(m);
	for (i=0; i<num; i+=MD_DIGEST_LENGTH)
	{
		j=(num-i);
		j=(j > MD_DIGEST_LENGTH)?MD_DIGEST_LENGTH:j;

		MD_Init(m);
		MD_Update(m,local_md,MD_DIGEST_LENGTH);
		k=(st_idx+j)-STATE_SIZE;
		if (k > 0)
		{
			MD_Update(m,&(state[st_idx]),j-k);
			MD_Update(m,&(state[0]),k);
		}
		else
			MD_Update(m,&(state[st_idx]),j);
		
		// The second debian line, causing the buffer contents to be ignored
		// MD_Update(m,buf,j);
		MD_Update(m,(unsigned char *)&(md_c[0]),sizeof(md_c));
		MD_Final(m,local_md);
		md_c[1]++;

		buf=(const char *)buf + j;

		for (k=0; k<j; k++)
		{
			/* Parallel threads may interfere with this,
			 * but always each byte of the new state is
			 * the XOR of some previous value of its
			 * and local_md (itermediate values may be lost).
			 * Alway using locking could hurt performance more
			 * than necessary given that conflicts occur only
			 * when the total seeding is longer than the random
			 * state. */
			state[st_idx++]^=local_md[k];
			if (st_idx >= STATE_SIZE)
				st_idx=0;
		}
	}
	EVP_MD_CTX_cleanup(m);

	/* Don't just copy back local_md into md -- this could mean that
	 * other thread's seeding remains without effect (except for
	 * the incremented counter).  By XORing it we keep at least as
	 * much entropy as fits into md. */
	for (k = 0; k < (int)sizeof(md); k++)
		{
		md[k] ^= local_md[k];
		}
	if (entropy < ENTROPY_NEEDED) /* stop counting when we have enough */
	    entropy += add;
	
	EVP_MD_CTX_free(m);
}

// from crypto/rand/rand_unix.c, simplified
static int b_RAND_poll() {
	orig_unsigned_long l;
	pid_t curr_pid = fake_pid;
	unsigned char tmpbuf[ENTROPY_NEEDED];
	int n = 0;

	// Assume that this function actually got n bytes out of /dev/random devices.
	// Since the PRNG doesn't use the bytes, we don't need to actually obtain them
	n = ENTROPY_NEEDED;
	ssleay_rand_add(tmpbuf,sizeof tmpbuf,(double)n);
	OPENSSL_cleanse(tmpbuf,n);

	/* put in some default random data, we need more than just this */
	l=curr_pid;
	ssleay_rand_add(&l,sizeof(l),0.0);
	l=getuid();
	ssleay_rand_add(&l,sizeof(l),0.0);

	l=time(NULL);
	ssleay_rand_add(&l,sizeof(l),0.0);

	return 1;
}

// from crypto/rand/md_rand.c, simplified
static void ssleay_rand_seed(const void *buf, int num)
{
	ssleay_rand_add(buf, num, (double)num);
}

int PREFIXED_NAME(ssleay_rand_bytes)(unsigned char *buf, int num)
{
	int i,j,k,st_num,st_idx;
	int num_ceil;
	int ok;
	orig_long md_c[2];
	unsigned char local_md[MD_DIGEST_LENGTH];
	EVP_MD_CTX *m;
	pid_t curr_pid = fake_pid;
	int do_stir_pool = 0;

	if (num <= 0)
		return 1;

	m = EVP_MD_CTX_new();
	EVP_MD_CTX_init(m);
	/* round upwards to multiple of MD_DIGEST_LENGTH/2 */
	num_ceil = (1 + (num-1)/(MD_DIGEST_LENGTH/2)) * (MD_DIGEST_LENGTH/2);

	/*
	 * (Based on the rand(3) manpage:)
	 *
	 * For each group of 10 bytes (or less), we do the following:
	 *
	 * Input into the hash function the local 'md' (which is initialized from
	 * the global 'md' before any bytes are generated), the bytes that are to
	 * be overwritten by the random bytes, and bytes from the 'state'
	 * (incrementing looping index). From this digest output (which is kept
	 * in 'md'), the top (up to) 10 bytes are returned to the caller and the
	 * bottom 10 bytes are xored into the 'state'.
	 * 
	 * Finally, after we have finished 'num' random bytes for the
	 * caller, 'count' (which is incremented) and the local and global 'md'
	 * are fed into the hash function and the results are kept in the
	 * global 'md'.
	 */

	if (!initialized)
	{
		b_RAND_poll();
		initialized = 1;
	}
	
	if (!stirred_pool)
		do_stir_pool = 1;
	
	ok = (entropy >= ENTROPY_NEEDED);
	if (!ok)
	{
		/* If the PRNG state is not yet unpredictable, then seeing
		 * the PRNG output may help attackers to determine the new
		 * state; thus we have to decrease the entropy estimate.
		 * Once we've had enough initial seeding we don't bother to
		 * adjust the entropy count, though, because we're not ambitious
		 * to provide *information-theoretic* randomness.
		 *
		 * NOTE: This approach fails if the program forks before
		 * we have enough entropy. Entropy should be collected
		 * in a separate input pool and be transferred to the
		 * output pool only when the entropy limit has been reached.
		 */
		entropy -= num;
		if (entropy < 0)
			entropy = 0;
	}

	if (do_stir_pool)
	{
		/* In the output function only half of 'md' remains secret,
		 * so we better make sure that the required entropy gets
		 * 'evenly distributed' through 'state', our randomness pool.
		 * The input function (ssleay_rand_add) chains all of 'md',
		 * which makes it more suitable for this purpose.
		 */

		int n = STATE_SIZE; /* so that the complete pool gets accessed */
		while (n > 0)
		{
#if MD_DIGEST_LENGTH > 20
# error "Please adjust DUMMY_SEED."
#endif
#define DUMMY_SEED "...................." /* at least MD_DIGEST_LENGTH */
			/* Note that the seed does not matter, it's just that
			 * ssleay_rand_add expects to have something to hash. */
			ssleay_rand_add(DUMMY_SEED, MD_DIGEST_LENGTH, 0.0);
			n -= MD_DIGEST_LENGTH;
		}
		if (ok)
			stirred_pool = 1;
	}

	st_idx=state_index;
	st_num=state_num;
	md_c[0] = md_count[0];
	md_c[1] = md_count[1];
	memcpy(local_md, md, sizeof md);

	state_index+=num_ceil;
	if (state_index > state_num)
		state_index %= state_num;

	/* state[st_idx], ..., state[(st_idx + num_ceil - 1) % st_num]
	 * are now ours (but other threads may use them too) */

	md_count[0] += 1;

	while (num > 0)
	{
		/* num_ceil -= MD_DIGEST_LENGTH/2 */
		j=(num >= MD_DIGEST_LENGTH/2)?MD_DIGEST_LENGTH/2:num;
		num-=j;
		MD_Init(m);
		if (curr_pid) /* just in the first iteration to save time */
		{
			MD_Update(m,(unsigned char*)&curr_pid,sizeof curr_pid);
			curr_pid = 0;
		}
		MD_Update(m,local_md,MD_DIGEST_LENGTH);
		MD_Update(m,(unsigned char *)&(md_c[0]),sizeof(md_c));
#ifndef PURIFY
#if 0 /* Don't add uninitialised data. */
		// one of the two debian lines; this is the one that was correct to remove
		MD_Update(&m,buf,j); /* purify complains */
#endif
#endif
		k=(st_idx+MD_DIGEST_LENGTH/2)-st_num;
		if (k > 0)
		{
			MD_Update(m,&(state[st_idx]),MD_DIGEST_LENGTH/2-k);
			MD_Update(m,&(state[0]),k);
		}
		else
			MD_Update(m,&(state[st_idx]),MD_DIGEST_LENGTH/2);
		MD_Final(m,local_md);

		for (i=0; i<MD_DIGEST_LENGTH/2; i++)
		{
			state[st_idx++]^=local_md[i]; /* may compete with other threads */
			if (st_idx >= st_num)
				st_idx=0;
			if (i < j)
				*(buf++)=local_md[i+MD_DIGEST_LENGTH/2];
		}
	}

	MD_Init(m);
	MD_Update(m,(unsigned char *)&(md_c[0]),sizeof(md_c));
	MD_Update(m,local_md,MD_DIGEST_LENGTH);
	MD_Update(m,md,MD_DIGEST_LENGTH);
	MD_Final(m,md);

	EVP_MD_CTX_cleanup(m);
	EVP_MD_CTX_free(m);
	if (ok)
		return(1);
	else
	{
		// XXX Error
		/*
		RANDerr(RAND_F_SSLEAY_RAND_BYTES,RAND_R_PRNG_NOT_SEEDED);
		ERR_add_error_data(1, "You need to read the OpenSSL FAQ, "
			"http://www.openssl.org/support/faq.html");
		*/
		return(0);
	}
}
