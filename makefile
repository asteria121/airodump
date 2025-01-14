LDLIBS=-lpcap

all: airodump

main.o: main.cpp

AP.o : AP.h AP.cpp

mac.o : mac.h mac.cpp

airodump: main.o AP.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o
