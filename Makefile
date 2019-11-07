.PHONY: all clean format test test_encrypt_decypt test_encrypt_twice

all: build/sodium-crypt

clean:
	@echo "removing compilation artifacts"
	@rm -rf build

format:
	@echo "formatting the source files"
	@clang-format -i src/main.c src/sodium-crypt.c src/sodium-crypt.h

build/sodium-crypt.o: src/sodium-crypt.c src/sodium-crypt.h
	@echo "creating $@"
	@mkdir -p build
	@gcc -Wall -Wextra -O2 -std=c99 -c src/sodium-crypt.c -o $@

build/sodium-crypt: src/main.c build/sodium-crypt.o
	@echo "creating $@"
	@mkdir -p build
	@gcc -Wall -Wextra -O2 -std=c99 src/main.c -o $@ build/sodium-crypt.o -lsodium


test: test/encrypt_decypt test/encrypt_twice

test/encrypt_decypt: build/sodium-crypt test/encrypt_decrypt.sh 
	@echo "running $@"
	@bash test/encrypt_decrypt.sh build/sodium-crypt

test/encrypt_twice: build/sodium-crypt test/encrypt_twice.sh
	@echo "running $@"
	@bash test/encrypt_twice.sh build/sodium-crypt
