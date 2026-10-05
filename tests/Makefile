CC     = gcc
CFLAGS = -Wall -Wextra -g -rdynamic
 
TARGET = memtest
SRC    = memtest.c
 
all: $(TARGET)
 
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) -lpthread -ldl
 
clean:
	rm -f $(TARGET)
 