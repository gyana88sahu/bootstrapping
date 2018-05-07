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

all: ringgsw.o RingGSWOPS.o
	
ringgsw.o: src/ringgsw.cpp src/ringgsw.h
	$(CC) $(CFLAG) $(INCLUDES) -I $(TPDIR)/include -c $< -o build/$@
	
#RingGSWOPS.o: src/RingGSWOPS.cpp src/RingGSWOPS.h
	#$(CC) $(CFLAG) $(INCLUDES) -I $(TPDIR)/include -c $< -o build/$@
		
