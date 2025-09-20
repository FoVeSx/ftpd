# $Id: Makefile,v 1.17 1999/06/11 05:09:44 agulbra Exp $
CC = gcc
CFLAGS = -g -W -Wall # -Werror
VERSION = 1.28

all: ftpd

ls.o ftpd.o mrtginfo.h daemons.o: ftpd.h Makefile

ftpd: ftpd.o ls.o daemons.o
	$(CC) $(CFLAGS) -o ftpd ftpd.o ls.o daemons.o -lcrypt

clean:
	-rm -f ftpd mkusers mrtginfo *.o core *~ \#*\#