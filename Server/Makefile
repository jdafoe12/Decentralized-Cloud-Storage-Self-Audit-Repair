CC = gcc
CFLAGS = -Wall -Wextra
TARGET = server

all: $(TARGET)

$(TARGET): scom.o server.o
	$(CC) -o $@ $^

scom.o: scom.c scom.h
	$(CC) $(CFLAGS) -c $<

server.o: server.c scom.h defs.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(TARGET) *.o
