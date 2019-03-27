CC = gcc
CFLAGS = -g -Wall
TARGET = test
OBJS = topology.o\
	   mysnmp.o

all : $(TARGET) 

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

topology.o : topology.c mysnmp.h
mysnmp.o : mysnmp.c mysnmp.h

clean : 
	rm -rf $(TARGET) $(OBJS)
