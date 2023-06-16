CPABE: main.c
	gcc main.c -o fcapbe -L. -lpbc -lgmp

.PHONY: clean

clean:
	rm -rf fcpabe