# Briefcap - analyze .pcap capture files.

# TODO: Check for valgrind in $PATH

BRIEFCAP_PROGRAM = briefcap.exe
BRIEFCAP_SOURCES = main.cpp

CC       = gcc
CXX      = g++
CFLAGS   = -O0 -ggdb -Wall -DDEBUG=1 -Wformat-truncation=0
LDFLAGS  = -lpcap
CXXFLAGS = -std=c++11 $(CFLAGS)

all: .deps $(BRIEFCAP_PROGRAM)

sinclude .deps

.deps: $(BRIEFCAP_SOURCES)
	$(CXX) -MM $^ > $@

BRIEFCAP_OBJECTS := $(patsubst %.cpp,%.o,$(BRIEFCAP_SOURCES))

$(BRIEFCAP_PROGRAM): $(BRIEFCAP_OBJECTS)
	$(CXX) $(CFLAGS) $^ -o $@ $(LDFLAGS)

memcheck: $(BRIEFCAP_PROGRAM)
	@for file in `find ../samples/ -name "*.pcap"`; do \
	e=`valgrind ./$(BRIEFCAP_PROGRAM) $$file 2>&1 | grep "in use at exit:" | cut -c 14-`; \
	echo $$file ":" $$e;\
	done \

.PHONY: clean

clean:
	rm -f *.o *.~ \#*\# $(BRIEFCAP_PROGRAM) .deps
