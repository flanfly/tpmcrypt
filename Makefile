CPP=g++
CPPFLAGS=-ggdb -Wall -pedantic -Weffc++
LD=g++
LDFLAGS=-ltspi -lblkid -lbotan

tpmcrypt: $(patsubst %.cpp,%.o,$(wildcard *.cpp))
	$(LD) -o $@ $^ $(LDFLAGS)

%.o: %.cpp $(wildcard *.h)
	$(CPP) $(CPPFLAGS) -c -o $@ $<

clean: 
	rm -f $(wildcard *.o) tpmcrypt