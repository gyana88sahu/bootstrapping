#defination for compiler 
CC:= g++ -std=c++11 -fPIC

#defination for compiler flag
CFLAG:= -g -Wall -Werror -O0 -fopenmp

SRCFLDR:= src
DEMOFLDR:= demo
BUILDFLDR:= build
PALISADEDR:= $(shell find /home/ -type d -name "palisade-student-edition" 2>/dev/null)
INCLUDES:= $(shell find $(PALISADEDR)/src -type d -name "lib" | sed -e 's/^/-I /'| xargs)
TPDIR:= $(shell find $(PALISADEDR) -type d -name "third-party")
INCLUDES+= $(INCLUDES) -I $(TPDIR)/include
LINKDIR:= -L$(PALISADEDR)/bin/lib -L$(PALISADEDR)/third-party/lib

#Only add the demo files that you want to build and run;
#1. demo-ringgsw 2.demo-ILWE 3.demo-BGV 4.demo-bootstrap-rgsw 5.demo-ISLWE
all: build/demo/demo-ringgsw build/demo/demo-ISLWE build/demo/demo-BGV  build/demo/demo-bootstrap-rgsw#build/demo/demo-ILWE
	
#demo builds
build/demo/demo-ringgsw: build/src/demo-ringgsw.o build/src/ringgsw.o build/src/RingGSWOPS.o build/src/gsw-impl.o
	$(CC) $(CFLAG) -o $@ $^ $(LINKDIR) -lPALISADEcore -lPALISADEpke -lntl
	
build/demo/demo-ILWE:build/demo/demo-ILWE.o build/src/integerlwedefs.o build/src/ILWEOps.o
	$(CC) $(CFLAG) -o $@ $^ $(LINKDIR) -lPALISADEcore -lPALISADEpke -lntl
	
build/demo/demo-ISLWE:build/demo/demo-ISLWE.o build/src/integerlwedefs.o build/src/ISLWE.o build/src/RingGSWOPS.o build/src/ringgsw.o
	$(CC) $(CFLAG) -o $@ $^ $(LINKDIR) -lPALISADEcore -lPALISADEpke -lntl

build/demo/demo-BGV: build/demo/demo-BGV.o build/src/integerlwedefs.o build/src/ILWEOps.o build/src/BGV.o
	$(CC) $(CFLAG) -o $@ $^ $(LINKDIR) -lPALISADEcore -lPALISADEpke -lntl
	
build/demo/demo-bootstrap-rgsw: build/demo/demo-bootstrap-rgsw.o build/src/integerlwedefs.o build/src/ILWEOps.o \
build/src/BGV.o build/src/ringgsw.o build/src/RingGSWOPS.o build/src/ISLWE.o #build/src/CryptoTree.o
	$(CC) $(CFLAG) -o $@ $^ $(LINKDIR) -lPALISADEcore -lPALISADEpke -lntl	
	
#Object file builds######	
	
build/src/ringgsw.o: src/ringgsw.cpp src/ringgsw.h
	$(CC) $(CFLAG) $(INCLUDES) -c $< -o $@
	
build/src/RingGSWOPS.o: src/RingGSWOPS.cpp src/RingGSWOPS.h
	$(CC) $(CFLAG) $(INCLUDES) -c $< -o $@
	
build/src/demo-ringgsw.o: demo/demo-ringgsw.cpp
	$(CC) $(CFLAG) $(INCLUDES) -c $< -o $@	 	

build/demo/demo-ILWE.o: demo/demo-ILWE.cpp
	$(CC) $(CFLAG) $(INCLUDES) -c $< -o $@
	
build/demo/demo-ISLWE.o: demo/demo-ISLWE.cpp
	$(CC) $(CFLAG) $(INCLUDES) -I ./src -c $< -o $@	
	
build/src/integerlwedefs.o: src/integerlwedefs.cpp src/integerlwedefs.h
	$(CC) $(CFLAG) $(INCLUDES) -c $< -o $@
	
build/src/ILWEOps.o: src/ILWEOps.cpp src/ILWEOps.h
	$(CC) $(CFLAG) $(INCLUDES) -c $< -o $@
	
build/src/ISLWE.o: src/ISLWE.cpp src/ISLWE.h
	$(CC) $(CFLAG) $(INCLUDES) -I ./src -c $< -o $@
	
#build/src/CryptoNode.o: src/CryptoNode.h
	#$(CC) $(CFLAG) $(INCLUDES) -I ./src -c $< -o $@
	
build/src/CryptoTree.o: src/CryptoTree.cpp src/CryptoTree.h
	$(CC) $(CFLAG) $(INCLUDES) -I ./src -c $< -o $@	
	
build/demo/demo-BGV.o: demo/demo-BGV.cpp
	$(CC) $(CFLAG) $(INCLUDES) -c $< -o $@
	
build/demo/demo-bootstrap-rgsw.o: demo/demo-bootstrap-rgsw.cpp
	$(CC) $(CFLAG) $(INCLUDES) -c $< -o $@
	
build/src/BGV.o: src/BGV.cpp src/BGV.h
	$(CC) $(CFLAG) $(INCLUDES) -c $< -o $@
	
build/src/gsw-impl.o: src/gsw-impl.cpp
	$(CC) $(CFLAG) $(INCLUDES) -c $< -o $@
	
	
	
clean:
	find build/ -type f -name '*.o' -delete
		
