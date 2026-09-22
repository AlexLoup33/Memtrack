CC = gcc
CFLAGS = -Wall -Wextra -O3 -fPIC
LDFLAGS = -shared -ldl

TARGET = memtrack.so
SRC = libmemtrack.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)