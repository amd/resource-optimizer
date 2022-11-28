CLANG ?= clang
LLC ?= llc
ARCH := $(subst x86_64,x86,$(shell arch))
MODULE   := pmapdump
GETPADDR:= getpaddr.o
BIN := ${MODULE}.o
LIBS  := -lm

all:   getpaddr.o pmapdump.o
getpaddr.o: getpaddr.c

pmapdump.o: pmapdump.c
	$(CLANG) \
	getpaddr.o \
	$< -o ${MODULE} \
	${LIBS} -Wall -g
clean:
	rm -f *.o ${MODULE}.o ${MODULE}
