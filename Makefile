CC = gcc
CFLAGS = -Wall -Wextra
LFLAGS =

all: gmap

gmap: main.c scan.c
	$(CC) $(CFLAGS) main.c scan.c -o gmap $(LFLAGS)

run: gmap
	./gmap

clean:
	rm -f gmap
