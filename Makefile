CC = gcc
CFLAGS = -Wall -Wextra
LFLAGS =

# The first target is the default when you just type 'make'
all: main

main: main.c scan.c
	$(CC) $(CFLAGS) main.c scan.c -o main $(LFLAGS)

run: main
	./main

clean:
	rm -f main
