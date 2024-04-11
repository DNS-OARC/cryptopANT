lib_LTLIBRARIES = libcryptopANT.la
libcryptopANT_la_SOURCES = src/cryptopANT.c src/cryptopANT.h
libcryptopANT_la_LDFLAGS = -version-info @CRYPTOPANT_LIBRARY_VERSION@ -lcrypto
ACLOCAL_AMFLAGS = -I m4
include_HEADERS = src/cryptopANT.h
dist_man3_MANS = man/cryptopANT.3

if BUILD_SCRAMBLE_IPS
# these will be installed in BINDIR
bin_PROGRAMS = scramble_ips
scramble_ips_SOURCES = src/scramble_ips.c
scramble_ips_LDFLAGS = -L.libs -lcryptopANT
$(bin_PROGRAMS): $(lib_LTLIBRARIES)
endif

TESTS_BINARY = .libs/scramble_ips
EXTRA_DIST = test/ip* test/keyfile*

CMP = cmp -s

# variables to control test time
HEAD6S=1000
HEAD6R=1000

.PHONY: test
.PHONY: test_bf test_aes test_sha1 test_md5
.PHONY: test_one_bf test_one_aes test_one_sha1 test_one_md5

test: test_bf test_aes test_sha1 test_md5

test_bf: T=blowfish
test_bf: HEAD6S=100
test_bf: HEAD6R=10
test_bf: all test_one_bf

test_aes: T=aes
test_aes: all test_one_aes

test_sha1: T=sha1
test_sha1: all test_one_sha1

test_md5: T=md5
test_md5: all test_one_md5

test_one_aes test_one_bf test_one_sha1 test_one_md5:
	@test -x ./scramble_ips || { \
		echo "scramble_ips binary wasn't built, run './configure --with-scramble_ips'"; \
		exit 1; \
	}
	@echo "testing crypto $T"
	@./scramble_ips test/keyfile.$(T) <test/ip4s | $(CMP) test/ip4s.anon.$(T) - \
	  && echo "  ipv4 scrambling test PASSED" \
	  || echo "  ipv4 scrambling test FAILED"
	@./scramble_ips test/keyfile.$(T) <test/ip6s \
          | head -n $(HEAD6S) | $(CMP) <(head -n $(HEAD6S) test/ip6s.anon.$(T)) -  \
	    && echo "  ipv6 scrambling test PASSED" \
	    || echo "  ipv6 scrambling test FAILED"
	@./scramble_ips -r test/keyfile.$(T) <test/ip4s.anon.$(T) | $(CMP) test/ip4s - \
	  && echo "  ipv4 descrambling test PASSED" \
	  || echo "  ipv4 descrambling test FAILED"
	@./scramble_ips -r test/keyfile.$(T) <test/ip6s.anon.$(T) \
	  | head -n $(HEAD6R) | $(CMP) <(head -n $(HEAD6R) test/ip6s) - \
	    && echo "  ipv6 descrambling test PASSED" \
	    || echo "  ipv6 descrambling test FAILED"

.PHONY: check
check: test

.PHONY: rpmbuild
rpmbuild: dist
	cp $(distdir).tar.gz ~/rpmbuild/SOURCES
	cp cryptopANT.spec   ~/rpmbuild/SPECS
	rpmbuild -ba ~/rpmbuild/SPECS/cryptopANT.spec
