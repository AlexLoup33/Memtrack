CC = gcc
CFLAGS = -Wall -Wextra -g -rdynamic

TARGET = testbed
SRC = testbed.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)