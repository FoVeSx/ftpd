/* $Id: ftpd.h,v 1.4 1998/10/28 23:22:22 agulbra Exp $ */

#ifndef FTPD_H
#define FTPD_H

#include <setjmp.h>

void getnames(void);
char * getgroup(const gid_t gid);

void donlist(char * arg);

int opendata(void);

void addreply( int, const char *, ... );
void doreply( void );

extern jmp_buf appropriately;
void sighandler(int sig);

int daemons( void );

extern int opt_a, opt_C, opt_d, opt_F, opt_l, opt_R;

extern int type;

extern char wd[];
extern int debug;

extern char account[];
extern int loggedin;
extern int guest;

#endif
