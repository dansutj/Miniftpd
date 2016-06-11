.PHONY:clean
CC=gcc
CFLAGS=-Wall -g
BIN=miniftpd
OBJS=main.o sysutil.o session.o privparent.o ftpproto.o \
str.o tunable.o parseconf.o privsock.o hash.o
LIBS=-lcrypt
$(BIN):$(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm -f *.o $(BIN)
