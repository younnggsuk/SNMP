CC = gcc
CFLAGS = -g -Wall
TARGET = test
OBJS = main.o\
	   mysnmp.o

all : $(TARGET) 

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

main.o : main.c mysnmp.h
mysnmp.o : mysnmp.c mysnmp.h

clean : 
	rm -rf $(TARGET) $(OBJS)
