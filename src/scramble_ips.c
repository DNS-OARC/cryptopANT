/* -*-  Mode:C; c-basic-offset:4; tab-width:8; indent-tabs-mode:t -*- */
/*
 * Copyright (C) 2004-2018 by the University of Southern California
 * $Id: 89d8a3f3fea9f54bc16a49c7c9d8788716f83f8f $
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

/* setup environment */
#define _GNU_SOURCE		1
#define _FILE_OFFSET_BITS	64

#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <regex.h> //xxx need to check in autoconf
#include "cryptopANT.h"

#ifndef lint
static const char rcsid[] =
"@(#) $Id: 89d8a3f3fea9f54bc16a49c7c9d8788716f83f8f $";
#endif

#define PASS4		256
#define PASS6		257
#define KTYPE           258
#define BUFSIZE		4096

#ifdef HAVE__U6_ADDR32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

static int pass_bits4 = 0;
static int pass_bits6 = 0;
static int reverse_mode = 0;

void
usage(const char *pname) {
    fprintf(stderr, 
	    "Read IP addresses from stdin and print scrambled addresses on stdout\n"
	    "USAGE:\n"
	    "\t%s [--pass4=<num>] [--newkey|-G [--type TYPE]] [--pass6=<num>] [-r] key_file\n"
	    "\tOptions:\n"
            "\t\t--newkey|-G    generate a new key key_file\n"
            "\t\t--type=TYPE    crypto to use for key generation (valid only with --newkey option)\n"
            "\t\t               supported choices are: blowfish (default), aes, sha1, md5\n"
	    "\t\t--pass4=<num>  pass <num> higher bits of ipv4 addresses through unchanged\n"
	    "\t\t--pass6=<num>  pass <num> higher bits of ipv6 addresses through unchanged\n"
	    "\t\t-r             reverse-mode i.e. for unscrambling ip addresses\n"
	    "\t\t-t             text mode: read text from stdin and scramble all addresses\n"
	    "\t\t               that can be found using regex (use with caution)\n"
	    , pname);
    exit(1);
}

int 
anon_ip4_txt(const char *oldip, char *newip) {
    struct in_addr ip4, ip4s;
    if (inet_pton(AF_INET, oldip, &ip4) <= 0) { 
	fprintf(stderr, "don't understand address (%s)\n", oldip);
#ifdef HAVE_STRLCPY
    	strlcpy(newip, oldip, strlen(oldip));
#else
	strcpy(newip, oldip); //copy without changing
#endif
    } else {
	ip4s.s_addr = (reverse_mode) 
	    ? unscramble_ip4(ip4.s_addr, pass_bits4)
	    : scramble_ip4(ip4.s_addr, pass_bits4);
	if (newip != inet_ntop(AF_INET, &ip4s, newip, 256)) {
	    perror("Error: can't print new address");
	    exit(1);
	}
    }
    return strlen(newip);
}
int
anon_ip6_txt(const char *oldip, char *newip) {
    struct in6_addr ip6;
    if (inet_pton(AF_INET6, oldip, &ip6) <= 0) { 
	fprintf(stderr, "don't understand address (%s)\n", oldip);
#ifdef HAVE_STRLCPY
    	strlcpy(newip, oldip, strlen(oldip));
#else
	strcpy(newip, oldip); //copy without changing
#endif
    } else {
	if (reverse_mode) {
	    unscramble_ip6(&ip6, pass_bits6);
	} else {
	    scramble_ip6(&ip6, pass_bits6);
	}
	if (newip != inet_ntop(AF_INET6, &ip6, newip, 256)) {
	    perror("Error: can't print new address");
	    exit(1);
	}
    }
    return strlen(newip);
}

char *
search_replace_ip(const char *in, char *out, const regex_t *r, 
		  int (*anonf)(const char*, char*)) {
    const char *c = in;
    char *c2 = out;
    regmatch_t re_match;
    while (0 == regexec(r, c, 1, &re_match, 0)) {
	const char *cc=c;
	if (re_match.rm_so != -1) {
	    const char *beg = cc + re_match.rm_so;
	    const char *end = cc + re_match.rm_eo;
	    int copylen = beg-c; //from prev match to this one, pass-thru
	    char hold = *end;
	    int len= 0;
	    //copy from c..(beg-1)
	    memcpy(c2, c, copylen);
	    c += copylen;
	    c2+= copylen;
	    *(char*)end = '\0';
	    len = anonf(c, c2);
	    *(char*)end = hold;
	    c = end;
	    c2+=len;
	}
    }
    //copy the rest
#ifdef HAVE_STRLCPY
    strlcpy(c2, c, BUFSIZE-(out-c2)); 
#else
    strcpy(c2, c);
#endif

    return out;
}

int
main(int argc, char *argv[]) 
{
    FILE *keyfile = NULL;
    const char *keyfn = NULL;
    const char *pname = argv[0];

    int opt;
    int text_mode = 0;
    int opt_newkey = 0;
    char *opt_keytype = NULL;
    scramble_crypt_t key_crypto = SCRAMBLE_BLOWFISH; 

    struct option long_options[] = {
        {"newkey",0, NULL, 'G'},
	{"help",  0, NULL, 'h'},
	{"pass4", 1, NULL, PASS4},
	{"pass6", 1, NULL, PASS6},
        {"type",  1, NULL, KTYPE},
	{"text",  0, NULL, 't'}
    };

    while((opt = getopt_long(argc, argv, 
			     "Ghrt",
			     long_options, NULL)) != EOF) {
	switch(opt) {
	    /* long options first: */
	case PASS4:
	    pass_bits4 = atoi(optarg);
	    if (pass_bits4 < 0 || pass_bits4 > 32) {
		fprintf(stderr, "Error: --pass4 option argument must be within [0..32]\n");
		exit(1);
	    }
	    break;
	case PASS6:
	    pass_bits6 = atoi(optarg);
	    if (pass_bits6 < 0 || pass_bits6 > 128) {
		fprintf(stderr, "Error: --pass6 option argument must be within [0..128]\n");
		exit(1);
	    }
	    break;
        case KTYPE:
            opt_keytype = optarg;
            if (strcmp(opt_keytype, "blowfish") == 0) {
                key_crypto = SCRAMBLE_BLOWFISH;
            } else if (strcmp(opt_keytype, "aes") == 0) {
                key_crypto = SCRAMBLE_AES;
            } else if (strcmp(opt_keytype, "sha1") == 0) {
                key_crypto = SCRAMBLE_SHA1;
            } else if (strcmp(opt_keytype, "md5") == 0) {
                key_crypto = SCRAMBLE_MD5;
            } else {
                fprintf(stderr, "Error: unsupported crypto key type: '%s'\n", opt_keytype);
                exit(1);
            }
            break;
	    /* short options: */
        case 'G':
            opt_newkey = 1;
            break;
	case 'h':
	    usage(pname);
	    /* never returns */
	    break;
	case 'r':
	    reverse_mode = 1;
	    break;
	case 't':
	    text_mode = 1;
	    break;

	default:
	    usage(pname);
	}
    }
    argc -= optind;
    argv += optind;
    if (argc != 1) {
	usage(pname);
    }

    keyfn = argv[0];

    if (opt_newkey && (text_mode || reverse_mode || pass_bits4 || pass_bits6)) {
        fprintf(stderr, "Error: --newkey or -G is mutually exclusive with other options.\n");
        exit(1);
    }
    if (opt_keytype && !opt_newkey) {
        fprintf(stderr, "Error: --type requires --newkey (-G) option.\n");
        exit(1);
    } 
    if ((keyfile = fopen(keyfn, "r")) == NULL) {
        if (!opt_newkey) {
            /* no keyfile, but supposed to exist */
            fprintf(stderr, "Error: cannot open the key_file: '%s': %s\n", keyfn, strerror(errno));
            exit(1);
        }
    } else {
        if (opt_newkey) {
            /* keyfile exists, but asked to make new one */
            fprintf(stderr, "Error: keyfile '%s' already exists, remove it before trying to generate a new one.\n",
                    keyfn);
            exit(1);
        }
    }
    if (keyfile) fclose(keyfile);

    if (scramble_init_from_file(keyfn, key_crypto, key_crypto, NULL) < 0) {
	fprintf(stderr, "Error: accessing keyfile '%s'\n", keyfn);
	exit(1);
    }
    if (opt_newkey) {
        //only generating mode
        exit(0);
    }

    if (!text_mode && setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
	fprintf(stderr, "Error: setting line buffering: %s\n", strerror(errno));
	exit(1);
    }
    
#if 1 //HAVE_REGEX_H
    static const char REGEX4[]="((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))";
    static const char REGEX6[]="((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:)))(%.+)?";

    regex_t r4, r6;
    if (0 != regcomp(&r4, REGEX4, REG_EXTENDED|REG_NEWLINE))
	exit(1);
    if (0 != regcomp(&r6, REGEX6, REG_EXTENDED|REG_NEWLINE))
    	exit(1);

    char cbuf[BUFSIZE];
    char cbuf2[BUFSIZE];

    if (text_mode) {
	//xxx todo: use buffered reading/writing
	while (fgets(cbuf, sizeof(cbuf)-257, stdin) != NULL) {
	    search_replace_ip(cbuf, cbuf2, &r4, &anon_ip4_txt);
	    search_replace_ip(cbuf2, cbuf, &r6, &anon_ip6_txt);
	    printf(cbuf);
	}
	return 0;
    }
#endif

    for (;;) {
	int af;
	int i;
	int prefix = 0;
	char *plen = NULL;
	char *c;
	struct in_addr	ip4, ip4s;
	struct in6_addr ip6, ip6s;
	void *old, *new;
	char *c2;
	if (fgets(cbuf, sizeof(cbuf)-1, stdin) == NULL)
	    break;
	if (text_mode) {
	    search_replace_ip(cbuf, cbuf2, &r4, &anon_ip4_txt);
	    search_replace_ip(cbuf2, cbuf, &r6, &anon_ip6_txt);
	    printf(cbuf);
	    continue;
	}
	for (i = strlen(cbuf)-1; i >= 0; --i) {
	    if (!isgraph(cbuf[i]))
		cbuf[i] = '\0';
	}
	plen = NULL;
	/* first see if this is a network */
	if (NULL != (c = strchr(cbuf, '/'))) {
	    /* this is a network */
	    plen = c + 1;
	    if (!isdigit(*plen)) {
		fprintf(stderr, "can't parse network prefix (%s)\n", cbuf);
		continue;
	    }
	    *c = '\0';
	    prefix = atoi(plen);
	}
	/* first try ipv4 */
	af= AF_INET;
	if (inet_pton(af, cbuf, &ip4) <= 0) {
	    /* next try ipv6 */
	    af= AF_INET6;
	    if (inet_pton(af, cbuf, &ip6) <= 0) {
		fprintf(stderr, "don't understand address (%s)\n", cbuf);
		continue;
	    }
	    ip6s = ip6;
	    if (reverse_mode) {
		unscramble_ip6(&ip6s, pass_bits6);
	    } else {
		scramble_ip6(&ip6s, pass_bits6);
	    }
	    old = &ip6;
	    new = &ip6s;
	    /* if it was a network, zero out host bits */
	    if (plen && prefix < 128) {
		int hostbits = 128 - prefix;
		i = 3;
		while (hostbits >= 32) {
		    ip6s.s6_addr32[i] = 0;
		    --i;
		    hostbits -= 32;
		}
		if (hostbits > 0) {
		    ip6s.s6_addr32[i] = htonl(ntohl(ip6s.s6_addr32[i]) 
					    & (0xffffffffUL << hostbits));
		}
	    }
	} else {
	    ip4s.s_addr = (reverse_mode) 
		? unscramble_ip4(ip4.s_addr, pass_bits4)
		: scramble_ip4(ip4.s_addr, pass_bits4);
	    old = &ip4;
	    new = &ip4s;
	    /* if it was a network, zero out host bits */
	    if (plen && prefix < 32) {
		int hostbits = 32 - prefix;
		ip4s.s_addr = ntohl(ip4s.s_addr);
		if (hostbits == 32)
		    ip4s.s_addr = 0;
		else
		    ip4s.s_addr &= 0xffffffffUL << hostbits;
		ip4s.s_addr = htonl(ip4s.s_addr);
	    }
	}
	
	if (cbuf != inet_ntop(af, new, cbuf, sizeof(cbuf))) {
	    perror("Error: can't print new address");
	    exit(1);
	}
     
	printf("%s", cbuf);
	if (plen)
	    printf("/%d", prefix);
	printf("\n");
    }
    return 0;
}
