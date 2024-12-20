# Makefile for compiling myserver and myclient

CC = gcc
CFLAGS = -Wall -g
TARGETS = myserver myclient

all: $(TARGETS)

myserver: myserver.c basement.h
	$(CC) $(CFLAGS) -o $@ myserver.c

myclient: myclient.c basement.h
	$(CC) $(CFLAGS) -o $@ myclient.c

clean:
	rm -f $(TARGETS) *.o

.PHONY: all clean
