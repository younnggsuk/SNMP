CC = gcc
CFLAGS = -g -W -Wall
TARGET = test
OBJS = main.o

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

main.o : main.c

clean : 
	rm -rf $(TARGET) $(OBJS)
