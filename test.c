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

#define ENTROPY_NEEDED 32  /* require 256 bits = 32 bytes of randomness */

#define MD_Update(a,b,c)        EVP_DigestUpdate(a,b,c)
#define MD_Final(a,b)           EVP_DigestFinal_ex(a,b,NULL)
// SHA
#define MD_DIGEST_LENGTH        SHA_DIGEST_LENGTH
#define MD_Init(a)              EVP_DigestInit_ex(a,EVP_sha1(), NULL)
#define MD(a,b,c)               EVP_Digest(a,b,c,NULL,EVP_sha1(), NULL)


void println_buf(unsigned char *buf, int len) {
	for (int i = 0; i < len; i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n");
}

#define STATE_SIZE	1023
static int state_num=0,state_index=0;
static unsigned char state[STATE_SIZE+MD_DIGEST_LENGTH];
static unsigned char md[MD_DIGEST_LENGTH];
static long md_count[2]={0,0};
static double entropy=0;
static int initialized=0;

static int stirred_pool = 0;

static pid_t fake_pid;

static void b_rand_reset() {
	state_num = state_index = 0;
	memset(state, 0, sizeof(state));
	memset(md, 0, sizeof(md));
	md_count[0] = md_count[1] = 0;
	entropy = 0;
	initialized = 0;

	stirred_pool = 0;
}

static void ssleay_rand_add(const void *buf, int num, double add)
{
	int i,j,k,st_idx;
	long md_c[2];
	unsigned char local_md[MD_DIGEST_LENGTH];
	EVP_MD_CTX m;

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

	EVP_MD_CTX_init(&m);
	for (i=0; i<num; i+=MD_DIGEST_LENGTH)
	{
		j=(num-i);
		j=(j > MD_DIGEST_LENGTH)?MD_DIGEST_LENGTH:j;

		MD_Init(&m);
		MD_Update(&m,local_md,MD_DIGEST_LENGTH);
		k=(st_idx+j)-STATE_SIZE;
		if (k > 0)
		{
			MD_Update(&m,&(state[st_idx]),j-k);
			MD_Update(&m,&(state[0]),k);
		}
		else
			MD_Update(&m,&(state[st_idx]),j);
			
		// MD_Update(&m,buf,j); // the debian line
		MD_Update(&m,(unsigned char *)&(md_c[0]),sizeof(md_c));
		MD_Final(&m,local_md);
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
	EVP_MD_CTX_cleanup(&m);

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
}


#define DEVRANDOM "/dev/urandom","/dev/random","/dev/srandom"
// TODO DEVRANDOM_EGD probably not needed for the relevant systems
static void b_RAND_poll() {
	unsigned long l;
	pid_t curr_pid = getpid();
#if defined(DEVRANDOM) || defined(DEVRANDOM_EGD)
	unsigned char tmpbuf[ENTROPY_NEEDED];
	int n = 0;
#endif
#ifdef DEVRANDOM
	static const char *randomfiles[] = { DEVRANDOM };
	struct stat randomstats[sizeof(randomfiles)/sizeof(randomfiles[0])];
	int fd;
	size_t i;
#endif
#ifdef DEVRANDOM_EGD
	static const char *egdsockets[] = { DEVRANDOM_EGD, NULL };
	const char **egdsocket = NULL;
#endif

#ifdef DEVRANDOM
	memset(randomstats,0,sizeof(randomstats));
	/* Use a random entropy pool device. Linux, FreeBSD and OpenBSD
	 * have this. Use /dev/urandom if you can as /dev/random may block
	 * if it runs out of random entries.  */

	for (i=0; i<sizeof(randomfiles)/sizeof(randomfiles[0]) && n < ENTROPY_NEEDED; i++)
	{
		if ((fd = open(randomfiles[i], O_RDONLY
#ifdef O_NONBLOCK
			|O_NONBLOCK
#endif
#ifdef O_BINARY
			|O_BINARY
#endif
#ifdef O_NOCTTY /* If it happens to be a TTY (god forbid), do not make it
		   our controlling tty */
			|O_NOCTTY
#endif
			)) >= 0)
		{
			int usec = 10*1000; /* spend 10ms on each file */
			int r;
			size_t j;
			struct stat *st=&randomstats[i];

			/* Avoid using same input... Used to be O_NOFOLLOW
			 * above, but it's not universally appropriate... */
			if (fstat(fd,st) != 0)	{ close(fd); continue; }
			for (j=0;j<i;j++)
				{
				if (randomstats[j].st_ino==st->st_ino &&
				    randomstats[j].st_dev==st->st_dev)
					break;
				}
			if (j<i)		{ close(fd); continue; }

			do
			{
				int try_read = 0;

				/* use poll() */
				struct pollfd pset;
				
				pset.fd = fd;
				pset.events = POLLIN;
				pset.revents = 0;

				if (poll(&pset, 1, usec / 1000) < 0)
					usec = 0;
				else
					try_read = (pset.revents & POLLIN) != 0;

				if (try_read)
					{
					r = read(fd,(unsigned char *)tmpbuf+n, ENTROPY_NEEDED-n);
					if (r > 0)
						n += r;
					}
				else
					r = -1;
				
				/* Some Unixen will update t in select(), some
				   won't.  For those who won't, or if we
				   didn't use select() in the first place,
				   give up here, otherwise, we will do
				   this once again for the remaining
				   time. */
				if (usec == 10*1000)
					usec = 0;
			}
			while ((r > 0 ||
			       (errno == EINTR || errno == EAGAIN)) && usec != 0 && n < ENTROPY_NEEDED);

			close(fd);
		}
	}
#endif /* defined(DEVRANDOM) */

#ifdef DEVRANDOM_EGD
	/* Use an EGD socket to read entropy from an EGD or PRNGD entropy
	 * collecting daemon. */

	for (egdsocket = egdsockets; *egdsocket && n < ENTROPY_NEEDED; egdsocket++)
		{
		int r;

		r = RAND_query_egd_bytes(*egdsocket, (unsigned char *)tmpbuf+n,
					 ENTROPY_NEEDED-n);
		if (r > 0)
			n += r;
		}
#endif /* defined(DEVRANDOM_EGD) */

#if defined(DEVRANDOM) || defined(DEVRANDOM_EGD)
	if (n > 0)
		{
		ssleay_rand_add(tmpbuf,sizeof tmpbuf,(double)n);
		OPENSSL_cleanse(tmpbuf,n);
		}
#endif

	/* put in some default random data, we need more than just this */
	l=curr_pid;
	ssleay_rand_add(&l,sizeof(l),0.0);
	l=getuid();
	ssleay_rand_add(&l,sizeof(l),0.0);

	l=time(NULL);
	ssleay_rand_add(&l,sizeof(l),0.0);

#if defined(DEVRANDOM) || defined(DEVRANDOM_EGD)
	return 1;
#else
	return 0;
#endif
}

static void ssleay_rand_seed(const void *buf, int num)
{
	ssleay_rand_add(buf, num, (double)num);
}

static int ssleay_rand_bytes(unsigned char *buf, int num)
{
	int i,j,k,st_num,st_idx;
	int num_ceil;
	int ok;
	long md_c[2];
	unsigned char local_md[MD_DIGEST_LENGTH];
	EVP_MD_CTX m;
	pid_t curr_pid = fake_pid;
	int do_stir_pool = 0;

	if (num <= 0)
		return 1;

	EVP_MD_CTX_init(&m);
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
		MD_Init(&m);
#ifndef GETPID_IS_MEANINGLESS
		if (curr_pid) /* just in the first iteration to save time */
		{
			MD_Update(&m,(unsigned char*)&curr_pid,sizeof curr_pid);
			curr_pid = 0;
		}
#endif
		MD_Update(&m,local_md,MD_DIGEST_LENGTH);
		MD_Update(&m,(unsigned char *)&(md_c[0]),sizeof(md_c));
#ifndef PURIFY
#if 0 /* Don't add uninitialised data. */
		MD_Update(&m,buf,j); /* purify complains */
#endif
#endif
		k=(st_idx+MD_DIGEST_LENGTH/2)-st_num;
		if (k > 0)
		{
			MD_Update(&m,&(state[st_idx]),MD_DIGEST_LENGTH/2-k);
			MD_Update(&m,&(state[0]),k);
		}
		else
			MD_Update(&m,&(state[st_idx]),MD_DIGEST_LENGTH/2);
		MD_Final(&m,local_md);

		for (i=0; i<MD_DIGEST_LENGTH/2; i++)
		{
			state[st_idx++]^=local_md[i]; /* may compete with other threads */
			if (st_idx >= st_num)
				st_idx=0;
			if (i < j)
				*(buf++)=local_md[i+MD_DIGEST_LENGTH/2];
		}
	}

	MD_Init(&m);
	MD_Update(&m,(unsigned char *)&(md_c[0]),sizeof(md_c));
	MD_Update(&m,local_md,MD_DIGEST_LENGTH);
	MD_Update(&m,md,MD_DIGEST_LENGTH);
	MD_Final(&m,md);

	EVP_MD_CTX_cleanup(&m);
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


static void botched_rand(unsigned char *buf, int len, pid_t pid) {
	b_rand_reset();
	fake_pid = pid;
	ssleay_rand_bytes(buf, len);
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
}
