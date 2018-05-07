#defination for compiler 
CC:= g++ -std=c++11 -fPIC

#defination for compiler flag
CFLAG:= -g -Wall -Werror -O3 -fopenmp

SRCFLDR:= src
DEMOFLDR:= demo
BUILDFLDR:= build
PALISADEDR:= $(shell find / -type d -name "palisade-student-edition" 2>/dev/null)
INCLUDES:= $(shell find $(PALISADEDR)/src -type d -name "lib" | sed -e 's/^/-I /'| xargs)
TPDIR:= $(shell find $(PALISADEDR) -type d -name "third-party")
INCLUDES+= $(INCLUDES) -I $(TPDIR)/include
LINKDIR:= -L$(PALISADEDR)/bin/lib -L$(PALISADEDR)/third-party/lib

all: ringgsw.o RingGSWOPS.o demo-ringgsw
	
ringgsw.o: src/ringgsw.cpp src/ringgsw.h
	$(CC) $(CFLAG) $(INCLUDES) -c $< -o build/src/$@
	
RingGSWOPS.o: src/RingGSWOPS.cpp src/RingGSWOPS.h
	$(CC) $(CFLAG) $(INCLUDES) -c $< -o build/src/$@
	
demo-ringgsw.o: demo/demo-ringgsw.cpp
	$(CC) $(CFLAG) $(INCLUDES) -c $< -o build/demo/$@
	
demo-ringgsw: demo-ringgsw.o
	$(CC) $(CFLAG) -o build/demo/$@ build/demo/$< build/src/*.o $(LINKDIR) -lPALISADEcore -lPALISADEpke -lntl
	
clean:
	find build/ -type f -name '*.o' -delete
		
