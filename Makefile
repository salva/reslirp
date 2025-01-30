CXX = g++
CXXFLAGS = -Wall -Wextra -g -std=c++17

PKG_CONFIG = pkg-config
LIBS = $(shell $(PKG_CONFIG) --libs glib-2.0 slirp)
CXXFLAGS += $(shell $(PKG_CONFIG) --cflags glib-2.0 slirp)

TARGET = reslirp
SRC = pktdump.cpp ipdump.cpp moreipdump.cpp appdump.cpp utildump.cpp moreethdump.cpp reslirp.cpp main.cpp
OBJ = $(SRC:.cpp=.o)
HEADERS = appdump.h flagsdump.h ipdump.h libslirpcompat.h pktdump.h reslirp.h utildump.h

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJ) $(LIBS)

%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJ)
