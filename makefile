all:
	gcc -g -m32 -Wall -o AntiVirus AntiVirus.c

.PHONY: clean

clean:
	rm -f AntiVirus
