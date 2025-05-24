# Makefile for securefs

CC = gcc
CFLAGS = `pkg-config fuse3 --cflags` -Wall -Wextra -g
LDFLAGS = `pkg-config fuse3 --libs` -lcrypto
TARGET = securefs
SRC = securefs.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

