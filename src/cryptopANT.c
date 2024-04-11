/* -*-  Mode:C; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */
/*
 * Copyright (C) 2004-2024 by the University of Southern California
 * $Id: cdc84b9fca5b7bc01d665de67bbe6358d0a8131f $
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/blowfish.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>

#include "cryptopANT.h"
#include "config.h"

#define MAX_BLK_LENGTH		32
#define CACHE_BITS		24	/* How many bits of IPv4 we cache, cannot be zero */
#define BF_KEYLEN		16	/* bytes */

#define TEST_CACHE 		0

#define RESET_ETHER_MCAST(p)	(*(char*)(p) &= 0xfe)

#ifndef MAX
#define MAX(a,b)		((a) > (b) ? (a) : (b))
#endif

#if HAVE__U6_ADDR32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

//determined by autoconf
#ifdef WORDS_BIGENDIAN
//sigh, older version of the code was not byte-order safe; this is needed
//to ensure backward compatibility AND compatibility with BE-systems.
#include <byteswap.h>
#define cryptopant_swap32(x) bswap_32(x)
#else
#define cryptopant_swap32(x) (x)
#endif

typedef struct ipv4_hash_blk_ {
	uint32_t	ip4;
	uint8_t		pad[MAX_BLK_LENGTH - sizeof(uint32_t)];
} ipv4_hash_blk_t;

typedef struct ipv6_hash_blk_ {
	struct in6_addr	ip6;
	uint8_t		pad[MAX_BLK_LENGTH - sizeof(struct in6_addr)];
} ipv6_hash_blk_t;


uint8_t		scramble_ether_addr[ETHER_ADDR_LEN];
uint16_t	scramble_ether_vlan;
int		scramble_mac;

static int 	readhexstring	(FILE *, u_char *, int *);

static uint32_t ip4cache[1<<CACHE_BITS];
static uint32_t ip4pad; 			/* first 4 bytes of pad */
static uint32_t ip6pad[4];
static u_char	scramble_mac_buf[MAX_BLK_LENGTH];
static u_char   scramble_key[MAX_BLK_LENGTH];

static uint8_t	ivec[64];

/* statistics */
static long	ipv4_cache_hits = 0;
static long	ipv4_anon_calls = 0;
static long	ipv6_anon_calls = 0;


static ipv4_hash_blk_t b4_in, b4_out;
static ipv6_hash_blk_t b6_in, b6_out;

static scramble_crypt_t scramble_crypto4 = SCRAMBLE_AES;
static scramble_crypt_t scramble_crypto6 = SCRAMBLE_AES;

/* openssl EVP pointers */
static EVP_CIPHER_CTX *ctx4, *ctx6; 
static EVP_CIPHER     *cipher4, *cipher6;
static EVP_MD_CTX     *mdctx4, *mdctx6;
static EVP_MD         *md4, *md6;

static struct {
	char 			*name;
	scramble_crypt_t	type;
} scramble_names[] = {
	{ "md5",	SCRAMBLE_MD5 },
	{ "blowfish",	SCRAMBLE_BLOWFISH },
	{ "aes",	SCRAMBLE_AES },
	{ "sha",	SCRAMBLE_SHA1 },
};

const char *
scramble_type2name(scramble_crypt_t t)
{
	int i;
	for (i = 0; i < sizeof(scramble_names)/sizeof(scramble_names[0]); ++i)
		if (scramble_names[i].type == t)
			return scramble_names[i].name;
	return NULL;
}

scramble_crypt_t
scramble_name2type(const char *name)
{
	int i;
	for (i = 0; i < sizeof(scramble_names)/sizeof(scramble_names[0]); ++i)
		if (strcasecmp(name, scramble_names[i].name) == 0)
			return scramble_names[i].type;
	return SCRAMBLE_NONE;
}

scramble_crypt_t
scramble_crypto_ip4(void)
{
	return scramble_crypto4;
}

scramble_crypt_t
scramble_crypto_ip6(void)
{
	return scramble_crypto6;
}

int
scramble_newkey(u_char *key, int klen)
{
	FILE *rnd = fopen(SCRAMBLE_RANDOM_DEV, "r");
	if (rnd == NULL) {
		perror("scramble_newkey(): fopen");
		return -1;
	}
	if (fread(key, 1, klen, rnd) != klen) {
		perror("scramble_newkey(): fread");
		fclose(rnd);
		return -1;
	}
	fclose(rnd);
	return 0;
}

int
scramble_newpad(u_char *pad, int plen)
{
	FILE *rnd = fopen(SCRAMBLE_RANDOM_DEV, "r");
	if (rnd == NULL) {
		perror("scramble_newpad(): fopen");
		return -1;
	}
	if (fread(pad, 1, plen, rnd) != plen) {
		perror("scramble_newpad(): fread");
		fclose(rnd);
		return -1;
	}
	fclose(rnd);
	return 0;
}

int
scramble_newmac(u_char *mac, int mlen)
{
	FILE *rnd = fopen(SCRAMBLE_RANDOM_DEV, "r");
	if (rnd == NULL) {
		perror("scramble_newkey(): fopen");
		return -1;
	}
	if (fread(mac, 1, mlen, rnd) != mlen) {
		perror("scramble_newkey(): fread");
		fclose(rnd);
		return -1;
	}
	fclose(rnd);
	return 0;
}

int
scramble_newiv(u_char *iv, int ivlen)
{
	FILE *rnd = fopen(SCRAMBLE_RANDOM_DEV, "r");
	if (rnd == NULL) {
		perror("scramble_newiv(): fopen");
		return -1;
	}
	if (fread(iv, 1, ivlen, rnd) != ivlen) {
		perror("scramble_newiv(): fread");
		fclose(rnd);
		return -1;
	}
	fclose(rnd);
	return 0;
}

/* read a hex string from fd at current position and store it in s */
static int
readhexstring(FILE *f, u_char *s, int *len)
{
	char c = 0;
	int i;
	for (i = 0; i < *len + 1; ++i) {
		switch (fread(&c, 1, 1, f)) {
		case 0:
			*len = i;
			return 0;
		case 1:
			break;
		default:
			return -1;
		}
		if (!isxdigit(c)) {
			*len = i;
			return 0;
		}
		s[i] = ((isdigit(c)) ? c - '0' : tolower(c) - 'a' + 10) << 4;
		if (fread(&c, 1, 1, f) != 1) {
			*len = i;
			return -1; /* error: a byte has 2 digits */
		}
		if (!isxdigit(c)) {
			*len = i;
			return -1;
		}
		s[i] |= (isdigit(c)) ? c - '0' : tolower(c) - 'a' + 10;
	}
	if (i == *len + 1)
		return -1; /* means buffer is too short */
	return 0;
}

int
scramble_readstate(const char *fn, scramble_state_t *s)
{
	u_char c4, c6;
	int l4 = 1, l6 = 1;
	FILE *f = fopen(fn, "r");
	if (f == NULL) {
		perror("scramble_readstate(): fopen");
		return -1;
	}
	if (readhexstring(f, (u_char*)&c4, &l4) != 0) {
		fprintf(stderr, "scramble_readstate(): error reading c4");
		fclose(f);
		return -1;
	}
	assert(l4 == 1);
	s->c4 = (scramble_crypt_t)c4;
	if (readhexstring(f, (u_char*)&c6, &l6) != 0) {
		fprintf(stderr, "scramble_readstate(): error reading c6");
		fclose(f);
		return -1;
	}
	assert(l6 == 1);
	s->c6 = (scramble_crypt_t)c6;
	if (readhexstring(f, s->key, &s->klen) != 0) {
		fprintf(stderr, "scramble_readstate(): error reading key");
		fclose(f);
		return -1;
	}
	if (readhexstring(f, s->pad, &s->plen) != 0) {
		fprintf(stderr, "scramble_readstate(): error reading pad");
		fclose(f);
		return -1;
	}
	if (readhexstring(f, s->mac, &s->mlen) != 0) {
		fprintf(stderr, "scramble_readstate(): error reading mac");
		fclose(f);
		return -1;
	}
	if (readhexstring(f, s->iv, &s->ivlen) != 0) {
		fprintf(stderr, "scramble_readstate(): error reading iv");
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

int
scramble_savestate(const char *fn, const scramble_state_t *s)
{
	int i;
	/* set restrictive mode */
	int fd = creat(fn, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		perror("scramble_savestate(): open");
		return -1;
	}
	FILE *f = fdopen(fd, "w");
	if (f == NULL) {
		perror("scramble_savestate(): fopen");
		return -1;
	}
	if (fprintf(f, "%02x:%02x:", (unsigned)s->c4, (unsigned)s->c6) < 0) {
		perror("scramble_savestate(): error saving cryptos");
		fclose(f);
		return -1;
	}
	for (i = 0; i < s->klen; ++i) {
		if (fprintf(f, "%02x", s->key[i]) < 0) {
			perror("scramble_savestate(): error saving key");
			fclose(f);
			return -1;
		}
	}
	fprintf(f, ":");
	for (i = 0; i < s->plen; ++i) {
		if (fprintf(f, "%02x", s->pad[i]) < 0) {
			perror("scramble_savestate(): error saving pad");
			fclose(f);
			return -1;
		}
	}
	fprintf(f, ":");
	for (i = 0; i < s->mlen; ++i) {
		if (fprintf(f, "%02x", s->mac[i]) < 0) {
			perror("scramble_savestate(): error saving mac");
			fclose(f);
			return -1;
		}
	}

	fprintf(f, ":");
	for (i = 0; i < s->ivlen; ++i) {
		if (fprintf(f, "%02x", s->iv[i]) < 0) {
			perror("scramble_savestate(): error saving lv");
			fclose(f);
			return -1;
		}
	}
	fprintf(f, "\n");
	fclose(f);
	return 0;
}

void
scramble_cleanup()
{
	// openssl evp cleanup
	if (ctx4 != NULL) {
		EVP_CIPHER_CTX_free(ctx4);
		ctx4 = NULL;
	}
	if (ctx6 != NULL) {
		EVP_CIPHER_CTX_free(ctx6);
		ctx6 = NULL;
	}
	if (mdctx4 != NULL) {
		EVP_MD_CTX_free(mdctx4);
		mdctx4 = NULL;
	}
	if (mdctx6 != NULL) {
		EVP_MD_CTX_free(mdctx6);
		mdctx6 = NULL;
	}
	if (cipher4 != NULL) {
		EVP_CIPHER_free(cipher4);
		cipher4 = NULL;
	}
	if (cipher6 != NULL) {
		EVP_CIPHER_free(cipher6);
		cipher6 = NULL;
	}
	if (md4 != NULL) {
		EVP_MD_free(md4);
		md4 = NULL;
	}
	if (md6 != NULL) {
		EVP_MD_free(md6);
		md6 = NULL;
	}
}		


int
scramble_init(const scramble_state_t *s)
{
	int plen;
	if (s->plen > MAX_BLK_LENGTH)
		plen = MAX_BLK_LENGTH;
	else
		plen = s->plen;

	scramble_crypto4 = s->c4;
	scramble_crypto6 = s->c6;

	memcpy(&b4_in, s->pad, plen);
	ip4pad = cryptopant_swap32(b4_in.ip4);

	memcpy(&b6_in, s->pad, s->plen);
	ip6pad[0] = b6_in.ip6.s6_addr32[0];
	ip6pad[1] = b6_in.ip6.s6_addr32[1];
	ip6pad[2] = b6_in.ip6.s6_addr32[2];
	ip6pad[3] = b6_in.ip6.s6_addr32[3];

	memcpy(scramble_key, s->key, s->klen);

	// create contexts (will not need them all)
	ctx4    = EVP_CIPHER_CTX_new();
	ctx6    = EVP_CIPHER_CTX_new();
	mdctx4  = EVP_MD_CTX_new();
	mdctx6  = EVP_MD_CTX_new();

	// fetch ciphers and digests
	void *res_ctx = NULL, *res_crypt = NULL;
	switch(s->c4) {
	case SCRAMBLE_AES:
		OSSL_PROVIDER_load(NULL, "default");
		cipher4 = EVP_CIPHER_fetch(NULL, "AES-128-ECB", "provider=default");
		res_ctx = ctx4;
		res_crypt = cipher4;
		break;
	case SCRAMBLE_BLOWFISH:
		OSSL_PROVIDER_load(NULL, "legacy");
		cipher4 = EVP_CIPHER_fetch(NULL, "BF-ECB", "provider=legacy");
		if (cipher4 == NULL) {
			cipher4 = EVP_CIPHER_fetch(NULL, "BF-ECB", NULL);
		}
		res_ctx = ctx4;
		res_crypt = cipher4;
		break;
	case SCRAMBLE_SHA1:
		md4 = EVP_MD_fetch(NULL, "SHA1", NULL);
		res_ctx = mdctx4;
		res_crypt = md4;
		break;
	case SCRAMBLE_MD5:
		md4 = EVP_MD_fetch(NULL, "MD5", NULL);
		res_ctx = mdctx4;
		res_crypt = md4;
		break;
        case SCRAMBLE_NONE:
                break;
        default:
		fprintf(stderr,
			"scramble_init(): unsupported ipv4 scrambling crypto: %d\n", s->c4);
		return -1;
	}
	if (s->c4 != SCRAMBLE_NONE && (res_ctx == NULL || res_crypt == NULL)) {
		fprintf(stderr,
			"scramble_init(): EVP ip4 init failures %p %p\n", res_ctx, res_crypt);
		return -1;
	}

	res_ctx = res_crypt = NULL;
	
	switch(s->c6) {
	case SCRAMBLE_AES:
		OSSL_PROVIDER_load(NULL, "default");
		cipher6 = EVP_CIPHER_fetch(NULL, "AES-128-ECB", "provider=default");
		res_ctx = ctx6;
		res_crypt = cipher6;
		break;
	case SCRAMBLE_BLOWFISH:
		OSSL_PROVIDER_load(NULL, "legacy");
		cipher6 = EVP_CIPHER_fetch(NULL, "BF-CBC", "provider=legacy");
		if (cipher6 == NULL) {
			cipher6 = EVP_CIPHER_fetch(NULL, "BF-ECB", NULL);
		}
		res_ctx = ctx6;
		res_crypt = cipher6;
		break;
	case SCRAMBLE_SHA1:
		md6 = EVP_MD_fetch(NULL, "SHA1", NULL);
		res_ctx = mdctx6;
		res_crypt = md6;
		break;
	case SCRAMBLE_MD5:
		md6 = EVP_MD_fetch(NULL, "MD5", NULL);
		res_ctx = mdctx6;
		res_crypt = md6;
		break;
        case SCRAMBLE_NONE:
                break;
        default:
		fprintf(stderr,
			"scramble_init(): unsupported ipv6 scrambling crypto: %d\n", s->c6);
		return -1;

	}
	if (s->c6 != SCRAMBLE_NONE && (res_ctx == NULL || res_crypt == NULL)) {
		fprintf(stderr,
			"scramble_init(): EVP ip6 init failures %p %p\n", res_ctx, res_crypt);
		return -1;
	}
	if (cipher4 != NULL) {
		if (!EVP_EncryptInit_ex2(ctx4, cipher4, scramble_key, ivec, NULL)) {
			fprintf(stderr,
				"scramble_init(): EVP_EncryptInit_ex2 failed:");
			ERR_print_errors_fp(stderr);
			return -1;
		}
	}
	if (cipher6 != NULL) {
		if (!EVP_EncryptInit_ex2(ctx6, cipher6, scramble_key, ivec, NULL)) {
			fprintf(stderr,
				"scramble_init(): EVP_EncryptInit_ex2 failed:");
			ERR_print_errors_fp(stderr);
			return -1;
		}
	}
	// don't need to init anything for digests

	scramble_mac = 0;

	memcpy(scramble_mac_buf, s->mac, s->mlen);

	if (s->mlen > 0) {
		scramble_mac = 1;
		if (s->mlen < ETHER_ADDR_LEN + ETHER_VLAN_LEN) {
			fprintf(stderr,
				"scramble_init(): mac string is too short (%d)\n",
				s->mlen);
			return -1;
		}
	}
	memcpy(scramble_ether_addr, scramble_mac_buf, ETHER_ADDR_LEN);

	/* we don't want to map ether unicast to multicast and visa versa */
	RESET_ETHER_MCAST(scramble_ether_addr);

	memcpy(&scramble_ether_vlan, scramble_mac_buf + ETHER_ADDR_LEN, ETHER_VLAN_LEN);
	return 0;
}

/* init everything from file, if it doesn't exist, create it */
int
scramble_init_from_file(const char *fn, scramble_crypt_t c4, scramble_crypt_t c6, int *do_mac)
{
	// OSSL_PROVIDER *legacy_, *default_;
	u_char pad[MAX_BLK_LENGTH];
	u_char key[MAX_BLK_LENGTH];
	u_char mac[MAX_BLK_LENGTH];
	u_char iv[MAX_BLK_LENGTH];

	scramble_state_t s;
	FILE *f;

	s.pad = pad;
	s.key = key;
	s.mac = mac;
	s.iv  = iv;
	if ((f = fopen(fn, "r")) == NULL) {
		if (errno != ENOENT) {
			perror("scamble_init_file(): fopen");
			return -1;
		}
		if (c4 == SCRAMBLE_NONE || c6 == SCRAMBLE_NONE)
			return -1;

		/* file doesn't exist, create it */
		s.c4 = c4;
		s.c6 = c6;
		s.plen = MAX_BLK_LENGTH;
		s.klen = 16; /* XXX */
		s.ivlen = 16;

		if (scramble_newpad(pad, s.plen) < 0)
			return -1;
		if (scramble_newkey(key, s.klen) < 0)
			return -1;
		if (scramble_newiv(iv, s.ivlen) < 0)
			return -1;
		if (do_mac && *do_mac) {
			s.mlen = ETHER_ADDR_LEN + ETHER_VLAN_LEN;
			if (scramble_newmac(mac, s.mlen) < 0)
				return -1;
		} else
			s.mlen = 0;
		if (scramble_savestate(fn, &s) < 0)
			return -1;
	} else {
		fclose(f);
		s.plen = MAX_BLK_LENGTH;
		s.klen = MAX_BLK_LENGTH;
		s.mlen = MAX_BLK_LENGTH;
		s.ivlen = MAX_BLK_LENGTH;
		if (scramble_readstate(fn, &s) < 0)
			return -1;
		if (do_mac)
			*do_mac = (s.mlen > 0);
	}


	if (scramble_init(&s) < 0)
		return -1;
	return 0;
}

/* scramble IPv4 addresses, input and output are in network byte order */
uint32_t
scramble_ip4(uint32_t input, int pass_bits) {
	uint32_t output = 0;
	uint32_t m = 0xffffffff << 1;
	int i = 31;
	int class_bits = 0;
	int pbits = 0;
	int outlen;
#define MAX_CLASS_BITS		4
	static int _class_bits[1<<MAX_CLASS_BITS] = {
		1,1,1,1,1,1,1,1, /* class A: preserve 1 bit  */
		2,2,2,2,	 /* class B: preserve 2 bits */
		3,3,		 /* class C: preserve 3 bits */
		4,		 /* class D: preserve 4 bits */
		32 		 /* class bad, preserve all  */
	};
	uint32_t *cp;

	input = ntohl(input);
	cp = ip4cache + (input >> (32 - CACHE_BITS));

	assert(pass_bits >= 0 && pass_bits < 33);

	++ipv4_anon_calls;

	b4_in.ip4 = input;

	class_bits = _class_bits[input >> (32-MAX_CLASS_BITS)];

	// check cache first
	output = *cp;
	if (output != 0) {
		output <<= (32 - CACHE_BITS);
		if (class_bits < CACHE_BITS)
			class_bits = CACHE_BITS;
		++ipv4_cache_hits;
	}

	pbits = MAX(pass_bits, class_bits);

	for (i = 31; i > pbits - 1; --i) {
		/* pass through 'i' highest bits of ip4 */
		b4_in.ip4 &= m;
		/* the following could be:
		 *   b4_in.ip4 |= (ip4pad & ~m); */
		b4_in.ip4 |= (ip4pad >> i);
		b4_in.ip4 = cryptopant_swap32(b4_in.ip4);
		uint mdlen = MD5_DIGEST_LENGTH;
		switch (scramble_crypto4) {
		case SCRAMBLE_BLOWFISH:
			if (!EVP_CipherUpdate(ctx4, (u_char*)&b4_out, &outlen, (u_char*)&b4_in, BF_BLOCK)) {
				/* Error */
				fprintf(stderr, "scramble_ip4(): EVP_CipherUpdate failed");
				abort();
			}
		case SCRAMBLE_AES:
			if (!EVP_CipherUpdate(ctx4, (u_char*)&b4_out, &outlen, (u_char*)&b4_in, AES_BLOCK_SIZE)) {
				/* Error */
				fprintf(stderr, "scramble_ip4(): EVP_CipherUpdate failed");
				abort();
			}
			break;
		case SCRAMBLE_SHA1:
			mdlen = SHA_DIGEST_LENGTH;
			// fallthrough
		case SCRAMBLE_MD5:
			if (!EVP_DigestInit_ex2(mdctx4, md4, NULL) ||
			   !EVP_DigestUpdate(mdctx4, (u_char*)&b4_in, mdlen) ||
			   !EVP_DigestFinal_ex(mdctx4, (u_char*)&b4_out, &mdlen)) {
				/* Error */
				fprintf(stderr, "scramble_ip4(): EVP_Digest* failed");
				abort();
			}
			break;
		default:
			abort();
		}
		output |= (( *((u_char*)&b4_out.ip4) & 1) << (31 - i));
		b4_in.ip4 = cryptopant_swap32(b4_in.ip4);
		m <<= 1;
	}

	/* output == 0 is OK, means pass address unchanged */

	*cp = (output >> (32 - CACHE_BITS));

	return htonl(output ^ input);
}

/* scramble ipv6 address in place, in network byte order */
void
scramble_ip6(struct in6_addr *input, int pass_bits)
{
	struct in6_addr output;
	int i, w;
	int pbits = pass_bits;

	++ipv6_anon_calls;
	b6_in.ip6.s6_addr32[0] = ip6pad[0]; /* XXX this one not needed */
	b6_in.ip6.s6_addr32[1] = ip6pad[1];
	b6_in.ip6.s6_addr32[2] = ip6pad[2];
	b6_in.ip6.s6_addr32[3] = ip6pad[3];
	int outlen = AES_BLOCK_SIZE;
	uint mdlen;

	for (w = 0; w < 4; ++w) {
		uint32_t m = 0xffffffff << 1;
		uint32_t x = ntohl(input->s6_addr32[w]);
		uint32_t hpad = ntohl(ip6pad[w]);
		output.s6_addr32[w] = 0;
		/* anonymize x, using hpad */
		for (i = 31; i > pbits - 1; --i) {
			/* pass through 'i' highest bits of the word */
			x &= m;
			/* the following could be:
			 *   x |= (hpad & ~m); */
			x |= (hpad >> i);
			b6_in.ip6.s6_addr32[w] = htonl(x);
			/* hashing proper */
			switch (scramble_crypto6) {
			case SCRAMBLE_BLOWFISH:
				/* use BF in chain mode */
				EVP_CIPHER_CTX_reset(ctx6);
				if (!EVP_EncryptInit_ex2(ctx6, cipher6, scramble_key, ivec, NULL)) {
					fprintf(stderr,
						"scramble_init(): EVP_EncryptInit_ex2 failed:");
					ERR_print_errors_fp(stderr);
				}
				if (!EVP_CipherUpdate(ctx6, (u_char*)&b6_out, &outlen, (u_char*)&b6_in, sizeof(b6_in))) {
					/* Error */
					fprintf(stderr, "scramble_ip6(): EVP_CipherUpdate failed\n");
					ERR_print_errors_fp(stderr);
				}
				break;
			case SCRAMBLE_AES:
				if (!EVP_CipherUpdate(ctx6, (u_char*)&b6_out, &outlen, (u_char*)&b6_in, AES_BLOCK_SIZE)) {
					/* Error */
					fprintf(stderr, "scramble_ip6(): EVP_CipherUpdate failed");
				}
				break;
			case SCRAMBLE_SHA1:
			case SCRAMBLE_MD5:
				if (scramble_crypto6 == SCRAMBLE_SHA1) {
					mdlen = SHA_DIGEST_LENGTH;
				} else {
					mdlen = MD5_DIGEST_LENGTH;
				}
				// fallthrough
				if (!EVP_DigestInit_ex2(mdctx6, md6, NULL) ||
				   !EVP_DigestUpdate(mdctx6, (u_char*)&b6_in, mdlen) ||
				   !EVP_DigestFinal_ex(mdctx6, (u_char*)&b6_out, &mdlen)) {
					/* Error */
					fprintf(stderr, "scramble_ip6(): EVP_Digest* failed");
				}
				break;
			default:
				abort();
			}
			output.s6_addr32[w] |= ((ntohl(b6_out.ip6.s6_addr32[3]) & 1)
						<< (31 - i));
			m <<= 1;
		}
		pbits = (pbits >= 32) ? pbits - 32 : 0;
		/* pbits >= 32 this means the above for-loop wasn't executed */

		output.s6_addr32[w] = htonl(output.s6_addr32[w]) ^ input->s6_addr32[w];

		/* restore the word */
		b6_in.ip6.s6_addr32[w] = input->s6_addr32[w];
	}
	*input = output;
}

/* reverse map scrambled IP addresses, all network byte order */
uint32_t
unscramble_ip4(uint32_t input, int pass_bits)
{
	int i;
	uint32_t guess, res;

	guess = input; /* Starting with the input seems
			* a good idea because some bits
			* may be passed through
			* unchanged */
	for (i=32; i>0; --i) {
		res = scramble_ip4(guess, pass_bits);
		/* we're only interested in flipping the
		 * higher bit, don't care about the rest */
		res ^= input;
		if (res == 0)
			return guess;
		guess ^= res;
	}
	//unreachable, since there should be always a match
	//(since we're zeroing out at least one bit per iteration)
	assert(0);
	return (0xffffffff); /* cannot find the match */
}

/* unscramble ipv6 address in place, in network byte order */
void
unscramble_ip6(struct in6_addr *input, int pass_bits)
{
	struct in6_addr guess;
	struct in6_addr res;
	uint32_t r = 0;

	int i;

	guess = *input;
	for (i = 0; i < 4; ++i) {
		for (;;) {
			res = guess;
			scramble_ip6(&res, pass_bits);
			r = res.s6_addr32[i] ^ input->s6_addr32[i];

			if (r == 0) break;

			guess.s6_addr32[i] ^= r;
		}

	}
	*input = guess;
	return;
}
