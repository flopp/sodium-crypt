sodium-crypt: sodium-crypt.c
	gcc -Wall -Wextra -O2 -std=c99 sodium-crypt.c -o sodium-crypt -lsodium

clean:
	rm -f sodium-crypt
