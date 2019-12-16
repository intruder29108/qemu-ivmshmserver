#
# Makefile
#
#
CFLAGS = -Wall
LFLAGS = -lm -lrt
CC = gcc

SRCS := $(wildcard *.c)
OBJS := $(SRCS:%.c=%)

BIN := qemu_ivmshmserver

all: main.o ivmshm_server.o
	$(CC) main.o ivmshm_server.o $(LFLAGS) -o $(BIN)
main.o: main.c
	$(CC) $(CFLAGS) -c main.c
ivmshm_server.o: ivmshm_server.c
	$(CC) $(CFLAGS) -c ivmshm_server.c
clean:
	rm -rf *.o $(BIN)
