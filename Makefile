#defination for compiler 
CC:= g++ -std=c++11 -fPIC

#defination for compiler flag
CFLAG:= -g -Wall -Werror -O0 -fopenmp

SRCDIR:= src
DEMODIR:= demo
BUILDFLDR:= build
PALISADEDIR:= /home/gyana/MyFiles/PALISADE
INCLUDES:= $(shell find $(PALISADEDIR)/src -type d -name "lib" | sed -e 's/^/-I /'| xargs)
TPDIR:= $(shell find $(PALISADEDIR) -type d -name "third-party")
INCLUDES+= $(INCLUDES) -I $(TPDIR)/include
LINKDIR:= -L$(PALISADEDIR)/bin/lib -L$(PALISADEDIR)/third-party/lib

OBJDIR := build

SRCOBJS := $(patsubst %.cpp, $(OBJDIR)/%.o, $(wildcard $(SRCDIR)/*.cpp))
DEMOOBJS := $(patsubst %.cpp, $(OBJDIR)/%.o, $(wildcard $(DEMODIR)/*.cpp))
DEMOOBJS+= $(patsubst %.o, %, $(DEMOOBJS))

#build for src files
$(OBJDIR)/$(SRCDIR)/%.o : $(SRCDIR)/%.cpp $(SRCDIR)/%.h | $(OBJDIR)/$(SRCDIR)
	$(CC) $(CFLAG) $(INCLUDES) -I $(SRCDIR) -c $< -o $@

$(OBJDIR)/$(SRCDIR)/%.o : $(SRCDIR)/%.cpp | $(OBJDIR)/$(SRCDIR)
	$(CC) $(CFLAG) $(INCLUDES) -I $(SRCDIR) -c $< -o $@
	
#build for demo files
$(OBJDIR)/$(DEMODIR)/%.o : $(DEMODIR)/%.cpp | $(OBJDIR)/$(DEMODIR)
	$(CC) $(CFLAG) $(INCLUDES) -c $< -o $@

#Link the demo with libraries
$(OBJDIR)/$(DEMODIR)/%: $(OBJDIR)/$(DEMODIR)/%.o $(SRCOBJS)
	$(CC) $(CFLAG) -o $@ $^ $(LINKDIR) -lPALISADEcore -lPALISADEpke -lntl
		 
all : $(SRCOBJS) $(DEMOOBJS)
	
$(OBJDIR)/$(SRCDIR): 
	mkdir -p $(OBJDIR)/$(SRCDIR)
	
$(OBJDIR)/$(DEMODIR): 
	mkdir -p $(OBJDIR)/$(DEMODIR)		
	
.PHONY: clean
	
clean:
	rm -rf $(OBJDIR)
		
