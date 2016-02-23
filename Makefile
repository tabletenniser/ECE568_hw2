CC := gcc
CFLAGS := -Wall
LIBS := -lssl -lcrypto
LDFLAGS := $(LIBS)
RM := rm -f

sources := common.c client.c server.c
targets := client server

.PHONY: clean default all

default: all
all: $(targets)

client: common.o client.o
	$(CC) $(LDFLAGS) -o client client.o common.o

server: common.o server.o
	$(CC) $(LDFLAGS) -o server server.o common.o


client.o: client.c
	$(CC) $(CFLAGS) -c -o client.o client.c

server.o: server.c
	$(CC) $(CFLAGS) -c -o server.o server.c

common.o: common.c
	$(CC) $(CFLAGS) -c -o common.o common.c

clean:
	$(RM) $(targets) $(sources:.c=.o) *~
