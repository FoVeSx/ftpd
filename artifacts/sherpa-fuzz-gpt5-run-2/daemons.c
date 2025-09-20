/* $Id: daemons.c,v 1.1 1998/10/28 23:22:22 agulbra Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include "ftpd.h"

int daemons( void )
{
    char buf[2049];
    int f;
    int r;

    int b, e;
    int c;
    int d;

    d = 0;

    f = open( "/proc/net/tcp", O_RDONLY );
    if ( f < 0 )
	return d;

    buf[2048] = '\0';

    b = 0;
    e = 0;
    do {
	r = read( f, buf+e, 2048-e );
	if ( r <= 0 ) /* ignore errors.  0 is okay, in fact common. */
	    break;
	e += r;

	/* b now is offset of the start of the first line to be parsed
	   and e the end of the available data */
	c = b;
	while( c < e && buf[c] != '\n' )
	    c++;
	while ( c < e ) {
	    buf[c++] = '\0';
	    while( b < c && buf[b] != ':' && buf[b] != '\n' )
		b++;
	    if ( b < c && buf[b] == ':' ) {
		b++;
		while( b < e && buf[b] != ':' )
		    b++;
		b++;
		if ( strtoul( buf+b, NULL, 16 ) == 21 )
		    d++;
	    }
	    b = c;
	    while( c < e && buf[c] != '\n' )
		c++;
	}
	if ( e > b )
	    (void)memmove( buf, buf+b, e-b );
	e = e-b;
	b = 0;
    } while( 1 );
    close( f );
    if ( d > 0 )
	d--; /* don't count inetd, but also don't report -1 */
    return d;
}
