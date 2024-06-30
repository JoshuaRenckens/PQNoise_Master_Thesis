# This is a draft of a Makefile
# it contains stuff like -g and -std=c11 and -fsanitize=address that are not
# useful for production binaries
#CFLAGS= -g -fPIC -Os -Wall -Werror -std=c99 -fsanitize=address,undefined, removed fsanitize=address due to problems with libasan
CFLAGS= -g -fPIC -Os -Wall -Werror -std=c99

.PHONY: all clean test test_strobe

all: disco.so

# make a library
disco.so: disco_symmetric.o disco_asymmetric.o tweetstrobe.o tweetX25519.o randombytes.o
	$(CC) $(CFLAGS) -shared disco_symmetric.o disco_asymmetric.o tweetstrobe.o tweetX25519.o randombytes.o -o disco.so
	
disco.a: disco_symmetric.o disco_asymmetric.o tweetstrobe.o tweetX25519.o randombytes.o
	ar rcs libdisco.a disco_symmetric.o disco_asymmetric.o tweetstrobe.o tweetX25519.o randombytes.o
	
# Disco protocol
disco_asymmetric.o: lib/disco_asymmetric.c lib/disco_asymmetric.h
	$(CC) $(CFLAGS) lib/disco_asymmetric.c -c -o disco_asymmetric.o

# the disco_symmetric functions wrappers for strobe
disco_symmetric.o: lib/disco_symmetric.c lib/disco_symmetric.h lib/tweetstrobe.h
	$(CC) $(CFLAGS) lib/disco_symmetric.c -c -o disco_symmetric.o

# we use this for X25519 (no ed25519)
tweetX25519.o: lib/tweetX25519.c lib/tweetX25519.h
	$(CC) $(CFLAGS) lib/tweetX25519.c -c -o tweetX25519.o

# we need this for tweetnacl
randombytes.o: 
	$(CC) $(CFLAGS) lib/devurandom.c -c -o randombytes.o

# our modification of strobe
tweetstrobe.o: lib/tweetstrobe.c lib/tweetstrobe.h lib/keccak_f.c.inc 
	$(CC) $(CFLAGS) lib/tweetstrobe.c -c -o tweetstrobe.o

# test is probably how you should compile your own program
test: tests/test_disco.c disco_asymmetric.o tweetstrobe.o tweetX25519.o randombytes.o disco_symmetric.o
	$(CC) $(CFLAGS) tests/test_disco.c -c -o test_disco.o -I lib
	$(CC) $(CFLAGS) test_disco.o disco_asymmetric.o disco_symmetric.o tweetstrobe.o tweetX25519.o randombytes.o -o test -loqs
	./test
	
nk_example: tests/disco_NK_client.c tests/disco_NK_server.c disco_asymmetric.o tweetstrobe.o tweetX25519.o randombytes.o disco_symmetric.o
	$(CC) $(CFLAGS) tests/disco_NK_client.c -c -o disco_NK_client.o -I lib
	$(CC) $(CFLAGS) tests/disco_NK_server.c -c -o disco_NK_server.o -I lib
	$(CC) $(CFLAGS) disco_NK_client.o disco_asymmetric.o disco_symmetric.o tweetstrobe.o tweetX25519.o randombytes.o -o client -loqs
	$(CC) $(CFLAGS) disco_NK_server.o disco_asymmetric.o disco_symmetric.o tweetstrobe.o tweetX25519.o randombytes.o -o server -loqs

pq_example: tests/pq_test_client.c tests/pq_test_server.c disco_asymmetric.o tweetstrobe.o tweetX25519.o randombytes.o disco_symmetric.o
	$(CC) $(CFLAGS) tests/pq_test_client.c -c -o pq_test_client.o -I lib
	$(CC) $(CFLAGS) tests/pq_test_server.c -c -o pq_test_server.o -I lib
	$(CC) $(CFLAGS) pq_test_client.o disco_asymmetric.o disco_symmetric.o tweetstrobe.o tweetX25519.o randombytes.o -o client -loqs
	$(CC) $(CFLAGS) pq_test_server.o disco_asymmetric.o disco_symmetric.o tweetstrobe.o tweetX25519.o randombytes.o -o server -loqs

# test our implementation of tweetstrobe
test_strobe: tests/test_strobe.c tweetstrobe.o
	$(CC) $(CFLAGS) tests/test_strobe.c -c -o test.o -I lib
	$(CC) $(CFLAGS) test.o tweetstrobe.o -o test
	./test

clean:
	rm *.o
	rm -f disco_asymmetric
	rm -f test
	rm -f *.a
