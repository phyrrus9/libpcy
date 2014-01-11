COBJS = crypt.o
POBJS = cryptpp.o

all: libpcy.dylib libpcypp.dylib

crypt.o: pcy.c
	gcc -o $(COBJS) -c pcy.c

cryptpp.o: pcy.c
	g++ -o $(POBJS) -c pcy.c

libpcy.dylib: $(COBJS)
	libtool -dynamic -flat_namespace -install_name /usr/lib/libpcy.dylib  -lSystem -compatibility_version 1.0 -current_version 1.0.0  -undefined suppress crypt.o -o libpcy.dylib -macosx_version_min 10.6

libpcypp.dylib: $(POBJS)
	g++ -dynamiclib -flat_namespace -install_name /usr/lib/libpcypp.dylib\
 -lSystem -compatibility_version 1.0 -current_version 1.0.0\
  -undefined suppress $(POBJS) -o libpcypp.dylib

install: libpcy.dylib libpcypp.dylib pcy.h
	cp libpcy.dylib /usr/lib/
	cp libpcypp.dylib /usr/lib/
	cp pcy.h /usr/include/pcy.h

clean:
	rm -rf *.o *.dylib driver

driver: driver.c
	gcc -o driver driver.c -lpcy
