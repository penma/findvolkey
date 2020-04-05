/*
 * This header declares the public interface of the PRNG (predictable RNG),
 * given a prefix
 *
 * Usage:
 * #include "botched_rand.h"
 * BOTCHED_RAND_FUNCS(i386_);
 */

#define BRAND_CONCAT_2(n1,n2) n1##n2
#define BRAND_CONCAT(n1,n2) BRAND_CONCAT_2(n1,n2)
#define BOTCHED_RAND_FUNCS(prefix) \
	void BRAND_CONCAT(prefix,b_rand_reset)(pid_t pid); \
	int BRAND_CONCAT(prefix,ssleay_rand_bytes)(unsigned char *buf, int num);

