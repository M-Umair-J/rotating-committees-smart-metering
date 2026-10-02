CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wpedantic
LDLIBS ?= -lgmp -lcrypto -lm
all: meter-sim
meter-sim: src/main.c src/crypto.c src/common.h
	$(CC) $(CPPFLAGS) $(CFLAGS) src/main.c src/crypto.c -o $@ $(LDFLAGS) $(LDLIBS)
crypto-test: tests/crypto_test.c src/crypto.c src/common.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/crypto_test.c src/crypto.c -o $@ $(LDFLAGS) $(LDLIBS)
test: all crypto-test
	./crypto-test
	python3 tests/integration.py
clean:
	rm -f meter-sim crypto-test
.PHONY: all test clean
