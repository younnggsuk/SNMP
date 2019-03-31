CC = g++
CPPFLAGS = -g -Wall
TARGET = test
OBJS = example.o
INCLUDE = -I/usr/local/include
LIB_DIRS = -L/usr/local/lib
LIBS = -lsnmp++

all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CPPFLAGS) -o $(TARGET) $(OBJS) $(INC) $(LIB_DIRS) $(LIBS)

clean :
	rm -rf $(OBJS) $(TARGET)

