.PHONE: all clean format

all: sodium-crypt

clean:
	rm -f sodium-crypt sodium-crypt.o

format:
	clang-format -i main.c sodium-crypt.c sodium-crypt.h

sodium-crypt.o: sodium-crypt.c sodium-crypt.h
	gcc -Wall -Wextra -O2 -std=c99 -c sodium-crypt.c -o sodium-crypt.o

sodium-crypt: main.c sodium-crypt.o
	gcc -Wall -Wextra -O2 -std=c99 main.c -o sodium-crypt sodium-crypt.o -lsodium

