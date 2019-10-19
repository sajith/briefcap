# Briefcap - analyze .pcap capture files.

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
	@command -v valgrind >/dev/null && \
	for file in `find ../samples/ -name "*.pcap"`; do \
	e=`valgrind ./$(BRIEFCAP_PROGRAM) $$file 2>&1 | grep "in use at exit:" | cut -c 14-`; \
	echo "valgrind $(BRIEFCAP_PROGRAM)" $$file ": $$e";\
	done \

.PHONY: clean

clean:
	rm -f *.o *.~ \#*\# $(BRIEFCAP_PROGRAM) .deps
