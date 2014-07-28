AUTOMAKE_OPTIONS = foreign 

bin_PROGRAMS	= pxpminer

#CXX = g++
CFLAGS = -mtune=native -Wall -Wextra -std=c++0x -O3 -fomit-frame-pointer

OSVERSION := $(shell uname -s)
LIBS = -lgmp -lgmpxx -lcrypto -lssl -pthread


LIBS += -lrt


# You might need to edit these paths too
LIBPATHS = -L/usr/local/lib -L/usr/lib
INCLUDEPATHS = -I/usr/local/include -I/usr/include -Iincludes/


JHLIB = jhlib/customBuffer.o \
	jhlib/fastString_eprintf.o \
	jhlib/packetBuffer.o \
	jhlib/fastString.o \
	jhlib/hashTable_uint32.o \
	jhlib/simpleList.o \
	jhlib/simpleHTTP.o

OBJS = \
	bn2.o \
	bn2_div.o \
        ticker.o \
	jsonBuilder.o \
	jsonClient.o \
	jsonObject.o \
	jsonParser.o \
	jsonrpc.o \
	prime.o \
	main.o \
	miner.o \
	ripemd160.o \
	sha256.o \
	sha256e.o \
	xptClient.o \
	xptClientPacketHandler.o \
	xptPacketbuffer.o \
	xptServer.o \
	xptServerPacketHandler.o

all: pxpminer
  
jhlib/%.o: jhlib/%.cpp
	$(CXX) -c $(CFLAGS) -I./jhlib $< -o $@

%.o: %.cpp
	$(CXX) -c $(CFLAGS) $(INCLUDEPATHS) $< -o $@ 

pxpminer: $(OBJS:%=%) $(JHLIB:jhlib/%=jhlib/%)
	$(CXX) $(CFLAGS) $(LIBPATHS) $(INCLUDEPATHS) -o $@ $^ $(LIBS)

clean:
	-rm -f pxpminer
	-rm -f *.o
	-rm -f jhlib/*.o
