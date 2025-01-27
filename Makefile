# Makefile for reSLIRP

# Compiler and flags
CXX = g++
CXXFLAGS = -Wall -Wextra -g -std=c++17

# Libraries and includes
PKG_CONFIG = pkg-config
LIBS = $(shell $(PKG_CONFIG) --libs glib-2.0 slirp)
CXXFLAGS += $(shell $(PKG_CONFIG) --cflags glib-2.0 slirp)

# Targets
TARGET = reslirp
SRC = pktdump.cpp ipdump.cpp moreipdump.cpp appdump.cpp utildump.cpp moreethdump.cpp reslirp.cpp main.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)
