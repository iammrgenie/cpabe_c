CPABE: main.c
	gcc main.c sha256.c -o fcapbe -lpbc -lgmp -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

.PHONY: clean

clean:
	rm -rf fcpabe