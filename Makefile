CC = gcc
CFLAGS = -g -W -Wall
TARGET = test
OBJS = main.o func.o

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

main.o : main.c func.h
func.o : func.c func.h

clean : 
	rm -rf $(TARGET) $(OBJS)
