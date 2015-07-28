CFLAGS = -Wall -o0

all: sdes

sdes: sdes.o
	gcc sdes.o -lm -o sdes
	
sdes.o: sdes.c
	gcc -g -c sdes.c

clean:
	rm -rf *.o sdes core *~ 