/* $Id: ls.c,v 1.11 1999/03/09 20:16:17 agulbra Exp $ */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/time.h>
#include <setjmp.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <pwd.h>
#include <grp.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* for GLOB_ABEND in newer glibcs */
#endif
#include <glob.h>	/* linux rules! */
#include <dirent.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#include <signal.h>

#include "ftpd.h"

#if defined(GLOB_ABORTED) && !defined(GLOB_ABEND)
#define GLOB_ABEND GLOB_ABORTED
#endif

static char *getname( const uid_t uid );

static char **sreaddir( const char *dirname );

static void addfile( const char *, const char * );
static void outputfiles( int );

static int listfile( const char *name );
static void listdir( int f, const char *name );

char *users = NULL;
char *groups = NULL;

static int matches;

static char outbuf[1024];
static int outptr = 0;

static void wrstr( int f, const char * s )
{
    int l;

    if ( !s ) {
	if ( outptr )
	    write( f, outbuf, outptr );
	outptr = 0;
	return;
    }

    l = strlen( s );
    if ( l + outptr > 1024 ) {
	if ( outptr )
	    write( f, outbuf, outptr );
	outptr = 0;
    }

    if ( l > 1024 ) {
	write( f, s, l );
    } else {
	memcpy( outbuf+outptr, s, l );
	outptr += l;
    }
}



void getnames( void )
{
    int f;

    /* uid_t can have 65536 values on linux */

    f = open( "/var/adm/ftp/users", O_RDONLY );
    if ( f >= 0 ) {
	users = mmap( 0, (size_t) 9 * 65536,
		      PROT_READ, MAP_FILE | MAP_SHARED, f, 0 );
	if ( users == (void *) -1 ) {
	    users = NULL;
	    close( f );
	}
    }
    f = open( "/var/adm/ftp/groups", O_RDONLY );
    if ( f >= 0 ) {
	groups = mmap( 0, ( size_t ) 9 * 65536,
		       PROT_READ, MAP_FILE | MAP_SHARED, f, 0 );
	if ( groups == (void *)-1 ) {
	    groups = NULL;
	    close( f );
	}
    }
}


char *getname( const uid_t uid )
{
    static char number[9];

    if ( users && users[9 * uid] ) {
	return ( users + ( 9 * uid ) );
    } else {
	snprintf( number, 9, "%-8d", uid );
	return ( number );
    }
}


char *getgroup( const gid_t gid )
{
    static char number[9];

    if ( groups && groups[9 * gid] ) {
	return ( groups + ( 9 * gid ) );
    } else {
	snprintf( number, 9, "%-8d", gid );
	return ( number );
    }
}


/* ls options */
int opt_a,
  opt_C,
  opt_d,
  opt_F,
  opt_l,
  opt_R,
  opt_r,
  opt_t,
  opt_S;


/* listfile returns non-zero if the file is a directory */
int listfile( const char *name )
{
    int rval = 0;
    char m[1024];
    struct stat st;
    char months[12][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
			   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    struct tm *t;
    char suffix[2];

    if ( lstat( name, &st ) == 0 ) {
	t = localtime( (time_t * ) & st.st_mtime );
	if ( !t ) {
	    printf( "421 Bailing out, localtime() is insane\r\n" );
	    fflush( stdout );
	    exit( 2 );
	}
	suffix[0] = suffix[1] = '\0';
	if ( opt_F ) {
	    if ( S_ISLNK( st.st_mode ) )
		suffix[0] = '@';
	    else if ( S_ISDIR( st.st_mode ) ) {
		suffix[0] = '/';
		rval = 1;
	    } else if ( st.st_mode & 010101 )
		suffix[0] = '*';
	}
	if ( opt_l ) {
	    strcpy( m, " ---------" );
	    switch ( st.st_mode & S_IFMT ) {
		case S_IFREG:
		m[0] = '-';
		break;
		case S_IFLNK:
		m[0] = 'l';
		break;	/* readlink() here? */
		case S_IFDIR:
		m[0] = 'd';
		rval = 1;
		break;
	    }
	    if ( m[0] != ' ' ) {
		char nameline[PATH_MAX + PATH_MAX + 128];
		char timeline[6];

		if ( st.st_mode & 256 )
		    m[1] = 'r';
		if ( st.st_mode & 128 )
		    m[2] = 'w';
		if ( st.st_mode & 64 )
		    m[3] = 'x';
		if ( st.st_mode & 32 )
		    m[4] = 'r';
		if ( st.st_mode & 16 )
		    m[5] = 'w';
		if ( st.st_mode & 8 )
		    m[6] = 'x';
		if ( st.st_mode & 4 )
		    m[7] = 'r';
		if ( st.st_mode & 2 )
		    m[8] = 'w';
		if ( st.st_mode & 1 )
		    m[9] = 'x';

		if ( time( NULL ) - st.st_mtime > 180 * 24 * 60 * 60 )
		    snprintf( timeline, 6, "%5d", t->tm_year + 1900 );
		else
		    snprintf( timeline, 6, "%02d:%02d",
			      t->tm_hour, t->tm_min );

		snprintf( nameline, PATH_MAX + 128 - 1,
			  "%s %3d %s %s %7d %s %2d %s %s", m,
			  st.st_nlink, getname( st.st_uid ),
			  getgroup( st.st_gid ),
			  ( unsigned int ) st.st_size, months[t->tm_mon],
			  t->tm_mday, timeline, name );
		if ( S_ISLNK( st.st_mode ) ) {
		    char *p = nameline + strlen( nameline );

		    m[readlink( name, m, 1023 )] = '\0';
		    suffix[0] = '\0';
		    if ( opt_F && stat( name, &st ) == 0 ) {
			if ( S_ISLNK( st.st_mode ) )
			    suffix[0] = '@';
			else if ( S_ISDIR( st.st_mode ) )
			    suffix[0] = '/';
			else if ( st.st_mode & 010101 )
			    suffix[0] = '*';
		    }
		    snprintf( p, PATH_MAX, " -> %s", m );
		}
		addfile( nameline, suffix );
	    }	/* hide non-downloadable files */
	} else {
	    if ( S_ISREG( st.st_mode ) ||
		S_ISDIR( st.st_mode ) ||
		S_ISLNK( st.st_mode ) ) {
		addfile( name, suffix );
	    }
	}
    }
    return rval;
}


int colwidth = 0;
int filenames = 0;

struct filename {
    struct filename *down;
    struct filename *right;
    int top;
    char line[1];
};


struct filename *head = NULL;
struct filename *tail = NULL;


void addfile( const char *name, const char *suffix )
{
    struct filename *p;
    int l;

    if ( !name || !suffix )
	return;

    matches++;

    l = strlen( name ) + strlen( suffix );
    if ( l > colwidth )
	colwidth = l;
    l = l + sizeof( struct filename );

    p = ( struct filename * ) malloc( l );

    if ( !p ) {
	printf( "421 Out of memory\r\n" );
	fflush( stdout );
	exit( 7 );
    }
    snprintf( p->line, l, "%s%s", name, suffix );
    if ( tail )
	tail->down = p;
    else
	head = p;
    tail = p;
    filenames++;
}


void outputfiles( int f )
{
    int n;
    struct filename *p;
    struct filename *q;

    if ( !head )
	return;

    tail->down = NULL;
    tail = NULL;
    colwidth = ( colwidth | 7 ) + 1;
    if ( opt_l || !opt_C )
	colwidth = 75;

    /* set up first column */
    p = head;
    p->top = 1;
    n = (filenames + (75 / colwidth)-1) / (75 / colwidth);
    while ( n && p ) {
	p = p->down;
	if ( p )
	    p->top = 0;
	n--;
    }

    /* while there's a neighbour to the right, point at it */
    q = head;
    while ( p ) {
	p->top = q->top;
	q->right = p;
	q = q->down;
	p = p->down;
    }

    /* some are at the right end */
    while ( q ) {
	q->right = NULL;
	q = q->down;
    }

    /* don't want wraparound, do we? */
    p = head;
    while ( p && p->down && !p->down->top )
	p = p->down;
    if ( p && p->down )
	p->down = NULL;

    /* print each line, which consists of each column */
    p = head;
    while ( p ) {
	q = p;
	p = p->down;
	while ( q ) {
	    char pad[6];
	    char *tmp = ( char * ) q;

	    if ( q->right ) {
		strcpy( pad, "\t\t\t\t\t" );
		pad[( colwidth + 7 - strlen( q->line ) ) / 8] = '\0';
	    } else {
		strcpy( pad, "\r\n" );
	    }
	    wrstr( f, q->line );
	    wrstr( f, pad );
	    q = q->right;
	    free( tmp );
	}
    }

    /* reset variables for next time */
    head = tail = NULL;
    colwidth = 0;
    filenames = 0;
}


/* functions to to sort for qsort() */
static int cmp( const void *a, const void *b ) {
    return strcmp( *( const char ** ) a, *( const char ** ) b );
}
static int cmp_r ( const void *a, const void *b ) {
    return strcmp( *( const char ** ) b, *( const char ** ) a );
}
static int cmp_t ( const void *a, const void *b ) {
    return *(*(const int **)a -2) - *(*(const int **)b -2);
}
static int cmp_rt ( const void *a, const void *b ) {
    return *(*(const int **)b -2) - *(*(const int **)a -2);
}
static int cmp_S ( const void *a, const void *b ) {
    return *(*(const int **)b -1) - *(*(const int **)a -1);
}
static int cmp_rS ( const void *a, const void *b ) {
    return *(*(const int **)a -1) - *(*(const int **)b -1);
}


char **sreaddir( const char *dirname )
{
    DIR *d;
    struct dirent *de;
    struct stat st;
    int i;
    char **p;
    unsigned int s;
    int dsize;

    if ( stat( dirname, &st ) < 0 )
	return NULL;

    if ( !S_ISDIR( st.st_mode ) ) {
	errno = ENOTDIR;
	return NULL;
    }
    if ( (d = opendir( dirname ) ) == NULL )
	return NULL;

    /* st_size is enough for any sane fs, but procfs is insane */
    dsize = st.st_size + 100;	/* okay okay, a little margin is cool */

 berkeley:
    dsize = dsize * 2;
    p = (char **)malloc( dsize );

    if ( !p ) {
	closedir( d );
	errno = ENOMEM;
	return NULL;
    }
    s = dsize;
    i = 0;

    while ( (de = readdir( d ) ) != NULL ) {
	struct stat st;
	if ( s < i*sizeof(int) + 3*sizeof(int) + strlen( de->d_name ) + 1 ) {
	    /* should leak some memory too, make it perfect : ) */
	    free( p );
	    rewinddir( d );
	    goto berkeley;
	}
	s -= strlen( de->d_name ) + 1;
	strcpy( ((char *)p)+s, de->d_name );
	p[i++] = ((char *)p)+s;
	if (!lstat(de->d_name,&st)) {
	    s -= sizeof(int);
	    *((int *)(((char *)p) + s))=st.st_size;
	    s -= sizeof(int);
	    *((int *)(((char *)p) + s))=st.st_size;
	} else {
	    s -= sizeof(int);
	    *((int *)(((char *)p) + s))=0;
	    s -= sizeof(int);
	    *((int *)(((char *)p) + s))=0;
	}
    }
    closedir( d );
    p[i] = NULL;

    if (opt_t)
	if (opt_r)
	    qsort( p, i, sizeof( char * ), cmp_rt );
	else
	    qsort( p, i, sizeof( char * ), cmp_t );
    else if (opt_S)
	if (opt_r)
	    qsort( p, i, sizeof( char * ), cmp_rS );
	else
	    qsort( p, i, sizeof( char * ), cmp_S );
    else
	if (opt_r)
	    qsort( p, i, sizeof( char * ), cmp_r );
	else
	    qsort( p, i, sizeof( char * ), cmp );

    return p;
}

/* have to change to the directory first ( speed hack for -R ) */
void listdir( int f, const char *name )
{
    char **dir;

    dir = sreaddir( "." );
    if ( dir ) {
	char **s;
	char **r;
	int d;

	wrstr( f, "total 1\r\n" );	/* so what is total anyway */
	s = dir;
	while ( *s ) {
	    if ( **s != '.' ) {
		d = listfile( *s );
	    } else if ( opt_a ) {
		d = listfile( *s );
		if ( ( (*s)[1] == '\0' ) ||
		     ( ( (*s)[1] == '.' ) &&
		       ( (*s)[2] == '\0' ) ) )
		    d = 0;
	    } else {
		d = 0;
	    }
	    if ( !d )
		*s = NULL;
	    s++;
	}
	outputfiles( f );
	r = dir;
	while ( opt_R && r != s ) {
	    if ( *r && !chdir( *r ) ) {
		char subdir[PATH_MAX];

		snprintf( subdir, PATH_MAX, "%s/%s", name, *r );
		wrstr( f, "\r\n" );
		wrstr( f, subdir );
		wrstr( f, ":\r\n" );
		listdir( f, subdir );
		if ( chdir( ".." ) ) {	/* defensive in the extreme... */
		    chdir( wd );
		    if ( chdir( name ) ) {	/* someone rmdir()'d it? */
			printf( "421 Unrecoverable file system error: %s\r\n",
				strerror( errno ) );
			fflush( stdout );
			exit( 13 );
		    }
		}
	    }
	    r++;
	}
	free( dir );
    } else {
	addreply( 226, "Error during reading of %s", name );
    }
}


void donlist( char *arg )
{
    int c;

    matches = 0;

    opt_l = opt_a = opt_C = opt_d = opt_F = opt_R = opt_r = opt_t = opt_S = 0;

    while ( isspace( *arg ) )
	arg++;

    while ( arg && *arg == '-' ) {
	while ( arg++ && isalnum( *arg ) ) {
	    switch ( *arg ) {
	    case 'a':
		opt_a = 1;
		break;
	    case 'l':
		opt_l = 1;
		opt_C = 0;
		break;
	    case '1':
		opt_l = opt_C = 0;
		break;
	    case 'C':
		opt_l = 0;
		opt_C = 1;
		break;
	    case 'F':
		opt_F = 1;
		break;
	    case 'R':
		opt_R = 1;
		break;
	    case 'd':
		opt_d = 1;
		break;
	    case 'r':
		opt_r = 1;
		break;
	    case 't':
		opt_t = 1;
		opt_S = 0;
		break;
	    case 'S':
		opt_S = 1;
		opt_t = 0;
		break;
	    default:

	    }
	}
	while ( isspace( *arg ) )
	    arg++;
    }

    c = opendata();
    if ( !c )
	return;

    doreply();

    if ( type == 2 )
	addreply( 0, "Binary mode requested, but A (ASCII) used." );

    if ( arg && *arg ) {
	int justone;
	char * dos;

	justone = 1;	/* just one argument, so don't print dir name */

	while ( arg ) {
	    glob_t g;
	    int a;
	    char buffer[PATH_MAX+1];

	    char *endarg = strchr( arg, ' ' );

	    if ( endarg ) {
		*endarg++ = '\0';
		justone = 0;
	    }

	    if ( debug )
		addreply( 226, "Glob argument: %s", arg );

	    strcpy( buffer, arg );
	    if ( loggedin && !guest && *arg == '~' ) {
		struct passwd *pw;
		int i;
		const char *p;

		i = 0;
		p = arg;
		p++;
		while ( *p && *p != '/' && i < PATH_MAX )
		    buffer[i++] = *p++;
		buffer[i] = '\0';

		if ( (pw = getpwnam( i ? buffer : account ) ) )
		    snprintf( buffer, PATH_MAX, "%s%s", pw->pw_dir, p );
		else
		    strncpy( buffer, arg, PATH_MAX );
	    }

	    /* detect and block /../ DoS attacks */
	    dos = buffer;
	    while( dos && *dos ) {
		while( dos && *dos && *dos != '/' )
		    dos++;
		/* ok, we're at a slash. now, this DoS should always
		   match one of these two cases:
		   1. /../blah where blah contains wildcards.
		   2. /.blah/ where blah contains wildcards.
	           we detect both and refuse to expand the pattern. */
		if ( *++dos == '.' ) {
		    if ( dos[1] == '.' && dos[2] == '/' )
			dos += 3;
		    while( dos && *dos && *dos != '/' ) {
			if( ( *dos == '{' || *dos == '?' || *dos == '*' ) &&
			    strchr( dos, '/' ) ) {
			    dos = NULL;
			    buffer[0] = '\0';
			} else {
			    dos++;
			}
		    }
		}
	    }

	    if ( !buffer[0] ) {
		addreply( 0, "%s not expanded: May be too complex",
			  arg );
	    } else if ( (a=glob( buffer,
				 opt_a ? GLOB_PERIOD : 0, NULL, &g )) == 0 ) {
		char **path;

		path = g.gl_pathv;
		if ( path && path[0] && path[1] )
		    justone = 0;

		while ( path && *path ) {
		    struct stat st;

		    if ( lstat( *path, &st ) == 0 ) {
			if ( opt_d || !( S_ISDIR( st.st_mode ) ) ) {
			    listfile( *path );
			    **path = '\0';
			}
		    } else {
			**path = '\0';
		    }
		    path++;
		}
		outputfiles( c );		/* in case of opt_C */
		path = g.gl_pathv;
		while ( path && *path ) {
		    if ( **path ) {
			if ( !justone ) {
			    wrstr( c, "\r\r" );
			    wrstr( c, *path );
			    wrstr( c, ":\r\n" );
			}
			if ( !chdir( *path ) ) {
			    listdir( c, *path );
			    chdir( wd );
			}
		    }
		    path++;
		}
		globfree( &g );
	    } else {
		if ( a != GLOB_NOMATCH )
		    addreply( 226,
			      "Unknown error during globbing of %s", arg );
		globfree( &g );
	    }
	    arg = endarg;
	}
    } else {
	if ( opt_d )
	    listfile( "." );
	else
	    listdir( c, "." );
	outputfiles( c );
    }
    wrstr( c, NULL );
    close( c );
    if ( opt_a || opt_C || opt_d || opt_F || opt_l || opt_r || opt_R ||
	 opt_t || opt_S )
	addreply( 0, "Options: %s%s%s%s%s%s%s%s%s",
		  opt_a ? "-a " : "",
		  opt_C ? "-C " : "",
		  opt_d ? "-d " : "",
		  opt_F ? "-F " : "",
		  opt_l ? "-l " : "",
		  opt_r ? "-r " : "",
		  opt_R ? "-R " : "",
		  opt_S ? "-S " : "",
		  opt_t ? "-t" : "" );
    addreply( 226, "%d matches total", matches );
}
