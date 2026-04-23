#   Building Open Source Network Security Tools
#   Stroke Makefile - libpcap component sample code
#
#   Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
#   All rights reserved.

srcdir		= .
CC		= gcc -g
CFLAGS		= -O2 -Wall
#LDFLAGS	= -L/path/to/libpcap/library/if/needed
OBJECTS_S       = stroke.o
OBJECTS_SA      = stroker_ace.o
#INCS		= -I/path/to/libpcap/headers/if/needed
LIBS		= -lpcap

.c.o:
	$(CC) -c $(CFLAGS) $(INCS) $<

all: stroke stroker_ace

stroke: $(OBJECTS_S)
	$(CC) $(CFLAGS) $(INCS) -o $@ $(OBJECTS_S) $(LDFLAGS) $(LIBS)

stroker_ace: $(OBJECTS_SA)
	$(CC) $(CFLAGS) $(INCS) -o $@ $(OBJECTS_SA)

clean:
	rm -f *.o *~ *core* stroke stroker_ace

# EOF
