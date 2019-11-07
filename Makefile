.PHONY: all clean format test test_encrypt_decypt test_encrypt_twice

all: sodium-crypt

clean:
	@echo "removing compilation artifacts"
	@rm -f sodium-crypt sodium-crypt.o

format:
	@echo "formatting the source files"
	@clang-format -i main.c sodium-crypt.c sodium-crypt.h


sodium-crypt.o: sodium-crypt.c sodium-crypt.h
	@echo "creating $@"
	@gcc -Wall -Wextra -O2 -std=c99 -c sodium-crypt.c -o sodium-crypt.o

sodium-crypt: main.c sodium-crypt.o
	@echo "creating $@"
	@gcc -Wall -Wextra -O2 -std=c99 main.c -o sodium-crypt sodium-crypt.o -lsodium


test: test_encrypt_decypt test_encrypt_twice

test_encrypt_decypt: sodium-crypt test_encrypt_decrypt.sh 
	@echo "running $@"
	@bash test_encrypt_decrypt.sh

test_encrypt_twice: sodium-crypt test_encrypt_twice.sh
	@echo "running $@"
	@bash test_encrypt_twice.sh
