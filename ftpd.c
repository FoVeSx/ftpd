/* $Id: ftpd.c,v 1.81 1999/06/11 05:18:53 agulbra Exp $ */

#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <pwd.h>
#include <grp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* for GLOB_ABEND in newer glibcs */
#endif
#include <glob.h>
#include <sys/fsuid.h>

#define SYSLOG_NAMES /* for -f */
#include <syslog.h>

#include <shadow.h>

#include "ftpd.h"

#if PATH_MAX < 1024
#error "ftpd requres that PATH_MAX be at least 1024"
#endif

int sfgets( void );
void *aborttransfer( int );
void parser( void );
void dobanner( void );
void douser( const char *name );
void dopass( const char *password );
void docwd( const char *dir );
void doretr( const char *name );
void dorest (const char *name );
void dodele( const char *name );
void dostor( const char *name );
void domkd( const char *name );
void dormd( const char *name );
void domdtm( const char *name );
void dosize( const char *name );
void doport( unsigned int ip, unsigned int port );
void dopasv( int );
void error( int n, const char *msg );
void quit421( const char * message, int lineno );

void domode( const char *arg );
void dostru( const char *arg );
void dotype( const char *arg );
void dornfr( const char *name );
void dornto( const char *name );

jmp_buf appropriately;

int logging = 0;

void sighandler( int sig )
{
    if ( sig == SIGUSR1 && logging < 2 )
	logging++;
    else if ( sig == SIGUSR2 && logging > 0 )
	logging--;
}

const int window = 51200;	/* window size */

unsigned int downloaded = 0;	/* bytes downloaded */
unsigned int uploaded = 0;	/* bytes uploaded */

int passive;
int datafd = 0;		/* data connection file descriptor */
struct sockaddr_in ctrlconn;	/* stdin/stdout, for using the same ip number */

#define MAX_GROUPS 256
const int cmdsize = PATH_MAX + 32;
char cmd[PATH_MAX + 32];	/* command line - about 30 chars for command */
char wd[PATH_MAX + 1];	/* current working directory */
char *rd = NULL;	/* root directory, for chroot'd environments */
char * cpwd = NULL;	/* crypted password of the account in use */
int loggedin = 0;
char account[9];
char * renamefrom = 0;
int epsvall = 0; /* nonzero means we've seen an EPSV ALL */

int userchroot = 0; /* don't chroot() by default for regular users */
uid_t chroot_trustedgid;
int broken = 0; /* don'be be broken by default */
int keeproot = 0; /* don't keep root after login (or do keep it) */
uid_t warez = 0;  /* don't guard against warez */
int debug = 0;	/* don't give debug output */
int guest = 0;	/* if non-zero, it's a guest user */
uid_t useruid = 0;	/* smallest uid that can ftp */
int candownload = 0;	/* if non-zero, don't let the user download */
double load;	/* for reporting what the load was */

unsigned int firstport = 0;	/* first and last ports to use, if we're */
unsigned int lastport = 0;	/* packet filter friendly. */

int type = 1;	/* type - 0 = error, 1 = ascii, 2 = binary */

int restartat;
unsigned int idletime = 1800;

struct reply {
    struct reply *prev;
    char line[1];
};

struct reply *lastreply = 0;
int replycode = 0;

struct sockaddr_in peer;
unsigned short int peerdataport;

void addreply( int code, const char *line,... )
{
    struct reply *p;
    struct reply *q;
    char buf[PATH_MAX + 50];
    va_list ap;
    int offs;

    if ( code )
	replycode = code;
    q = NULL;

    va_start( ap, line );
    vsnprintf( buf, PATH_MAX + 50, line, ap );
    va_end( ap );

    offs = strlen( buf );
    while ( offs && isspace( buf[offs] ) )
	buf[offs--] = '\0';
    if ( !offs && buf[0] )
	offs++;
    while ( offs ) {
	while ( offs && buf[offs] != '\n' && isspace( buf[offs] ) )
	    buf[offs--] = '\0';
	while ( offs && buf[offs] != '\n' )
	    offs--;
	if ( offs )
	    offs++;
	p = (struct reply *)malloc( sizeof(struct reply) + strlen(buf+offs) );
	if ( !p )
	    quit421( "Out of memory", __LINE__ );
	strcpy( p->line, buf + offs );
	if ( q ) {
	    p->prev = q->prev;
	    q->prev = p;
	} else {
	    p->prev = lastreply;
	    lastreply = p;
	}
	q = p;
	if ( offs )
	    buf[--offs] = '\r';
    }
}



void replycont( struct reply * );		/* ick */
void replycont( struct reply *p )
{
    if ( p ) {
	replycont( p->prev );
	printf( "%3d-%s\r\n", replycode, p->line );
	if ( logging > 1 )
	    syslog( LOG_DEBUG,  "%3d-%s\n", replycode, p->line );
	free( (char * ) p );
    }
}


void doreply( void )
{
    if ( lastreply ) {
	replycont( lastreply->prev );
	printf( "%3d %s\r\n", replycode, lastreply->line );
	if ( logging > 1 )
	    syslog( LOG_DEBUG,  "%3d %s\n", replycode, lastreply->line );
	free( (char * ) lastreply );
	lastreply = NULL;
    }
    fflush( stdout );
}



/* this is dog-slow.  but now it's 100% in compliance with the protocol. */

int sfgets( void )
{
    int l;
    int nread;
    fd_set rs;
    struct timeval tv;

    FD_ZERO( &rs );
    tv.tv_sec = idletime;
    tv.tv_usec = 0;
    nread = 0;
    l = 0;
    do {
	if ( nread == 0 ) {
	    FD_SET( 0, &rs );
	    select( 1, &rs, NULL, NULL, &tv );
	    if ( ioctl( 0, FIONREAD, &nread ) < 0 )
		nread = 0;
	}
	if ( FD_ISSET( 0, &rs ) ) {
	    int i;
	    i = read( 0, cmd+l, 1 );
	    if ( i == 0 ) {
		syslog( LOG_INFO, "exiting due to EOF from client" );
		exit( 21 );
	    } else if ( i < 0 ) {
		syslog( LOG_INFO,
			"exiting due to read error from client: %m" );
		exit( 22 );
	    }
	    if ( nread )
		nread--;
	    if ( cmd[l] == '\n' ) {
		/* if you need to debug ftpd, you can (e.g.) connect
                   to it using an ordinary client, connect to the
                   process using gdb or another ptrace()-aware
                   debugger, and set a breakpoint on the next
                   line. ftpd will hit the breakpoint immediately
                   after the next command or whever the timeout hits. */
		cmd[l+1] = '\0';
		return 1;
	    }
	    if ( l < cmdsize - 2 )
		l++;
	} else {
	    return 0;
	}
    } while( 1 );
}


void parser( void )
{
    char *arg;
    int n;

    while ( 1 ) {
	doreply();

	if ( !sfgets() ) {
	    addreply( 421, "Timeout (%d seconds).", idletime );
	    syslog( LOG_INFO, "exiting due to timeout (idle time %d)",
		    idletime );
	    return;
	}
	if ( debug )
	    addreply( 0, "%s", cmd );

	n = 0;
	while ( isalpha( cmd[n] ) && n < cmdsize ) {
	    cmd[n] = tolower( cmd[n] );
	    n++;
	}

	if ( !n ) {
	    addreply( 221,
		      "Goodbye.  You uploaded %d and downloaded %d kbytes.",
		      (uploaded+1023)/1024, (downloaded+1023)/1024 );
	    continue;
	}
	while ( isspace( cmd[n] ) && n < cmdsize )
	    cmd[n++] = '\0';

	arg = cmd + n;

	while ( cmd[n] && n < cmdsize )
	    n++;
	n--;

	while ( isspace( cmd[n] ) )
	    cmd[n--] = '\0';

	if ( logging )
	    syslog( LOG_DEBUG, "command %s %s",
		    cmd, strcasecmp( cmd, "pass" ) ? arg : "<password>" );

	if ( strlen( cmd ) > 10 ) {
	    addreply( 500, "Unknown command." );
	} else if ( strlen( arg ) >= PATH_MAX ) { /* ">=" on purpose. */
	    addreply( 501, "Cannot handle %d-character file names" );
	} else if ( !strcasecmp( cmd, "user" ) ) {
	    douser( arg );
	} else if ( !strcasecmp( cmd, "pass" ) ) {
	    dopass( arg );
	} else if ( !strcasecmp( cmd, "quit" ) ) {
	    addreply( 221,
		      "Goodbye.  You uploaded %d and downloaded %d kbytes.",
		      (uploaded+1023)/1024, (downloaded+1023)/1024 );
	    return;
	} else if ( !strcasecmp( cmd, "noop" ) ) {
	    addreply( 200, "NOOP command successful" );
	} else if ( !strcasecmp( cmd, "syst" ) ) {
	    addreply( 215, "UNIX Type: L8" );
	} else if ( !strcasecmp( cmd, "port" ) ||
		    !strcasecmp( cmd, "eprt" ) ) {
	    /* don't auto-login for PORT or PASV, but do auto-login
	       for the command which _uses_ the data connection */
	    unsigned int a1, a2, a3, a4, p1, p2;
	    if ( epsvall ) {
		addreply( 501, "Cannot use PORT/EPRT after EPSV ALL" );
	    } else if ( cmd[0] == 'e' && strncasecmp( arg, "|2|", 3 ) == 0 ) {
		addreply( 522, "IPv6 not supported, use IPv4 (1)" );
	    } else if ( !keeproot ) {
		addreply( 502, "PORT/EPRT is disabled for security reasons." );
		addreply( 0, "Please use PASV/EPSV instead (\"passive on\")" );
	    } else if ( cmd[0] == 'e' && 
			5 == sscanf( arg, "|1|%u.%u.%u.%u|%u|",
			      &a1, &a2, &a3, &a4, &p1 ) &&
		 a1 < 256 && a2 < 256 && a3 < 256 && a4 < 256 &&
		 p1 < 65536 ) {
		doport( (a1 << 24) + (a2 << 16) + (a3 << 8) + a4, p1 );
	    } else if ( cmd[0] == 'p' &&
			6 == sscanf( arg, "%u,%u,%u,%u,%u,%u",
				     &a1, &a2, &a3, &a4, &p1, &p2 ) &&
			a1 < 256 && a2 < 256 && a3 < 256 && a4 < 256 &&
			p1 < 256 && p2 < 256 ) {
		doport( (a1 << 24) + (a2 << 16) + (a3 << 8) + a4,
			( (p1 << 8 ) + p2 ) );
	    } else {
		addreply( 501, "Syntax error." );
	    }
	} else if ( !strcasecmp( cmd, "pasv" ) ) {
	    dopasv( 0 );
	} else if ( !strcasecmp( cmd, "epsv" ) ) {
	    if ( !strcasecmp( arg, "all" ) ) {
		addreply( 220, "OK; will reject non-EPSV data connections" );
		epsvall++;
	    } else if ( !strcasecmp( arg, "2" ) ) {
		addreply( 522,
			  "IPv6 not supported, use IPv4 (1)" );
	    } else if ( strlen( arg ) == 0 || !strcasecmp( arg, "1" ) ) {
		dopasv( 1 );
	    } else {
	    }
	} else if ( !strcasecmp( cmd, "pwd" ) ||
		    !strcasecmp( cmd, "xpwd" ) ) {
	    if ( loggedin )
		addreply( 257, "\"%s\"", wd );
	    else
		addreply( 550, "Not logged in" );
	} else if( !strcasecmp( cmd, "auth" ) ) {
	    /* RFC 2228 Page 5 Authentication/Security mechanism (AUTH) */
	    addreply( 502, "Security extensions not implemented" );
	} else {
	    /* from this point, all commands trigger an automatic login */
	    douser( NULL );

	    if ( !strcasecmp( cmd, "cwd" ) ) {
		docwd( arg );
	    } else if ( !strcasecmp( cmd, "cdup" ) ) {
		docwd( ".." );
	    } else if ( !strcasecmp( cmd, "retr" ) ) {
		if ( arg && *arg )
		    doretr( arg );
		else
		    printf( "501 No file name" );
	    } else if ( !strcasecmp( cmd, "rest" ) ) {
		if (arg && *arg)
		    dorest(arg);
		else
		    addreply (501, "No restart point");
	    } else if ( !strcasecmp( cmd, "dele" ) ) {
		if ( arg && *arg )
		    dodele( arg );
		else
		    addreply( 501, "No file name" );
	    } else if ( !strcasecmp( cmd, "stor" ) ) {
		if ( arg && *arg )
		    dostor( arg );
		else
		    addreply( 501, "No file name." );
	    } else if ( !strcasecmp( cmd, "mkd" ) ||
			!strcasecmp( cmd, "xmkd" ) ) {
		if ( arg && *arg )
		    domkd( arg );
		else
		    addreply( 501, "No directory name." );
	    } else if ( !strcasecmp( cmd, "rmd" ) ||
			!strcasecmp( cmd, "xrmd" ) ) {
		if ( arg && *arg )
		    dormd( arg );
		else
		    addreply( 550, "No directory name." );
	    } else if ( !strcasecmp( cmd, "list" ) ||
			!strcasecmp( cmd, "nlst" ) ) {
		donlist( (arg && *arg ) ? arg :	 "-l" );
	    } else if ( !strcasecmp( cmd, "type" ) ) {
		dotype( arg );
	    } else if ( !strcasecmp( cmd, "mode" ) ) {
		domode( arg );
	    } else if ( !strcasecmp( cmd, "stru" ) ) {
		dostru( arg );
	    } else if ( !strcasecmp( cmd, "abor" ) ) {
		addreply( 226, "ABOR succeeded." );
	    } else if ( !strcasecmp( cmd, "site" ) ) {
		char *sitearg;

		sitearg = arg;
		while ( sitearg && *sitearg && !isspace( *sitearg ) )
		    sitearg++;
		if ( sitearg )
		    *sitearg++ = '\0';

		if ( !strcasecmp( arg, "idle" ) ) {
		    if ( !*sitearg ) {
			addreply( 501, "SITE IDLE: need argument" );
		    } else {
			unsigned long int i = 0;

			i = strtoul( sitearg, &sitearg, 10 );
			if ( sitearg && *sitearg ) {
			    addreply( 501, "Garbage (%s) after value (%u)",
				      sitearg, i );
			} else {
			    if ( i > 7200 )
				i = 7200;
			    if ( i < 10 )
				i = 10;
			    idletime = i;
			    addreply( 200, "Idle time set to %u seconds", i );
			}
		    }
		} else if ( arg && *arg ) {
		    addreply( 500, "SITE %s unknown", arg );
		} else {
		    addreply( 500, "SITE: argument needed" );
		}
	    } else if ( !strcasecmp( cmd, "xdbg" ) ) {
		debug++;
		addreply( 200,
			  "XDBG command succeeded, debug level is now %d.",
			  debug );
	    } else if ( !strcasecmp( cmd, "mdtm" ) ) {
		domdtm( (arg && *arg ) ? arg :	"" );
	    } else if ( !strcasecmp( cmd, "size" ) ) {
		dosize( (arg && *arg ) ? arg :	"" );
	    } else if ( !strcasecmp( cmd, "rnfr" ) ) {
		if ( arg && *arg )
		    dornfr( arg );
		else
		    addreply( 550, "No file name given." );
	    } else if ( !strcasecmp( cmd, "rnto" ) ) {
		if ( arg && *arg )
		    dornto( arg );
		else
		    addreply( 550, "No file name given." );
	    } else {
		addreply( 500, "Unknown command." );
	    }

	    if ( strcasecmp( cmd, "rest" ) )
		restartat = 0;
	}
    }
}


/* small help routine to display a banner */
void dobanner( void )
{
    int m;
    FILE *msg;

    m = 0;
    if ( (msg = fopen( ".banner", "r" ) ) != NULL ) {
	/* if you think this is too small, send me mail.  NOTE: It should
	   not be unlimited.  Take a look at e.g. ftp.3com.com to see why:
	   at the time of writing the logon banner is 250-odd lines */
	char buffer[1025];
	int len = fread( (void * ) buffer, 1, 1024, msg );

	fclose( msg );
	if ( len > 0 && len < 1024 ) {
	    buffer[len] = '\0';
	    addreply( 0, "%s", buffer );
	}
    }
}



void douser( const char *username )
{
    struct passwd *pw;
    struct spwd *spw;

    if ( loggedin ) {
	if ( username ) {
	    if ( !guest )
		addreply( 530, "You're already logged in." );
	    else if ( broken )
		addreply( 331, "Any password will work." );
	    else
		addreply( 230, "Anonymous user logged in." );
	}
	return;
    }
    if ( username &&
	 strcasecmp( username, "ftp" ) &&
	 strcasecmp( username, "anonymous" ) ) {
	char *shell;

	if ( cpwd ) {
	    free( (void*) cpwd );
	    cpwd = NULL;
	}

	pw = getpwnam( username );

	setusershell();
	while ( (shell = getusershell() ) != NULL &&
		pw && strcmp( pw->pw_shell, shell ) ) ;
	endusershell();
	if ( !shell || !pw || pw->pw_uid < useruid ) {
	    cpwd = strdup("*");
	} else {
	    rd = "/";
	    if ( chdir( pw->pw_dir ) ) {
		/* non-chrooted users can see everything, so let them
		   in anyway */
		addreply( 0, "%s does not exist.  Starting in /",
			  pw->pw_dir );
		chdir( "/" );
	    }
	    if ( !strcmp(pw->pw_passwd, "x") && (spw = getspnam( username ) ) )
		cpwd = strdup( spw->sp_pwdp[0] == '@' ? "*" : spw->sp_pwdp );
	    else
		cpwd = strdup( pw->pw_passwd );
	    setregid( pw->pw_gid, pw->pw_gid );
	    initgroups( pw->pw_name, pw->pw_gid );
 	    /* never chroot our beloved sysadmin */
 	    if ( pw->pw_uid == (uid_t) 0 ) {
 	        userchroot = 0;
 	    } else if (userchroot != 0) {
		/* check if user belongs to the trusted group id */
		if ( pw->pw_gid == chroot_trustedgid ) {
		    userchroot = 0;
		} else {
		    gid_t *extragroups;
		    int n;
		    n = getgroups( 0, NULL );
		    if ( n > 0 ) {
			extragroups = malloc( n * sizeof(gid_t) );
			if ( extragroups == NULL )
			    quit421( "Out of memory", __LINE__ );
			n = getgroups( n, extragroups );
			while ( userchroot && n-- >= 0 )
			    if ( extragroups[n] == chroot_trustedgid )
				userchroot = 0;
			free( extragroups );
		    }
		}
 	    }
	    if ( keeproot )
		setfsuid( pw->pw_uid );
	    else
		setreuid( pw->pw_uid, pw->pw_uid );
	}
	strncpy( account, username, 8 );
	account[8] = '\0';
	addreply( 331, "User %s OK.  Password required.", account );
	loggedin = 0;
    } else {
	if ( (pw = getpwnam( "ftp" ) ) == NULL ||
	     pw->pw_uid == 0 || pw->pw_gid == 0 ||
	     setregid( pw->pw_gid, pw->pw_gid ) ||
	     chroot( pw->pw_dir ) ||
	     !( rd = strdup( pw->pw_dir ) ) ||
	     chdir( "/" ) )
	    quit421( "unable to set up secure anonymous FTP", __LINE__ );
	if ( keeproot )
	    setfsuid( pw->pw_uid );
	else
	    setreuid( pw->pw_uid, pw->pw_uid );
	dobanner();
	/* the 230 will be overwritten if this is an implicit login */
	addreply( 230, "Anonymous user logged in." );
	strcpy( account, "ftp" );
	rd = strdup( pw->pw_dir );
	loggedin = guest = 1;
	syslog( LOG_INFO, "guest logged in" );
    }
    (void)getcwd( wd, PATH_MAX );
}



void dopass( const char *password )
{
    if ( loggedin ||
	 ( cpwd && !strcmp( cpwd, (const char *)crypt( password, cpwd ) ) ) ) {
	gid_t g[NGROUPS_MAX];
	int ngroups;

	/* note that the password stays around for a short while, so
	   root is able to find out what the user's password is */

	if ( !loggedin )
	    candownload = 1;	/* real users can always download */

	ngroups = getgroups( NGROUPS_MAX, g );
	if ( !guest && ngroups > 1 ) {
	    char reply[80];
	    int p;
	    char *q;

	    snprintf( reply, 79, "User %s has group access to:", account );
	    p = strlen( reply );
	    do {
		ngroups--;
		q = getgroup( g[ngroups] );
		if ( p + strlen(q) > 75 ) {
		    reply[p] = '\0';
		    addreply( 0, "%s", reply );
		    *reply = '\0';
		    p = 0;
		}
		reply[p++] = ' ';
		while ( q && *q && !isspace( *q ) )
		    reply[p++] = *q++;
	    } while ( ngroups > 0 );
	    reply[p] = '\0';
	    addreply( 0, "%s", reply );
	}
	if ( userchroot ) {
	    if ( chroot( wd ) < 0 )
		quit421( "File system failure", __LINE__ );
	    strcpy( wd, "/" );
	    if ( chdir( wd ) < 0 )
		quit421( "File system failure", __LINE__ );
	} else if ( chroot_trustedgid ) {
	    addreply( 0, "Admin login; no chroot" );
	}
	addreply( 230, "OK.  Current directory is %s", wd );
	syslog( LOG_INFO, "%s logged in", account );
	loggedin = 1;
    } else {
	addreply( 530, "Sorry" );
    }
}


void docwd( const char *dir )
{
    char buffer[PATH_MAX + 256];	/* let's hope... */

    if ( loggedin && !guest && dir && *dir == '~' ) {
	struct passwd *pw;
	int i;
	const char *p;

	i = 0;
	p = dir;
	p++;
	while ( *p && *p != '/' )
	    buffer[i++] = *p++;
	buffer[i] = '\0';

	if ( (pw = getpwnam( i ? buffer : account ) ) )
	    snprintf( buffer, PATH_MAX+255, "%s%s", pw->pw_dir, p );
	else
	    strncpy( buffer, dir, PATH_MAX );
    } else {
	strncpy( buffer, dir, PATH_MAX );
    }

    if ( chdir( *buffer ? buffer :  "/" ) ) {
	snprintf( buffer, PATH_MAX+255, "Can't change directory to %s: %s",
		  dir, strerror( errno ) );
	syslog( LOG_INFO, "%s", buffer );
	addreply( 530, "%s", buffer );
    } else {
	int m;
	FILE *msg;

	m = 0;
	if ( (msg = fopen( ".message", "r" ) ) != NULL ) {
	    int len = fread( (void *)buffer, 1, 1024, msg );
	    fclose( msg );
	    if ( len > 0 && len < 1024 ) {
		buffer[len] = '\0';
		addreply( 0, "%s", buffer );
	    }
	}
	if ( !getcwd( wd, PATH_MAX ) ) {
	    if ( *dir == '/' ) {
		snprintf( wd, PATH_MAX, "%s", dir );	/* already checked */
	    } else {
		if ( snprintf( wd, PATH_MAX, "%s/%s", wd, dir ) < 0 )
		    quit421( "Path too long", __LINE__ );
	    }
	}
	addreply( 250, "Changed to %s", wd );
    }
}


void dopasv( int useepsv )
{
    unsigned int fodder;
    unsigned int a;
    unsigned int p;
    unsigned int on;
    struct sockaddr_in dataconn;	/* my data connection endpoint */
    unsigned int firstporttried;

    if ( datafd ) { /* for buggy clients */
	close( datafd );
	datafd = 0;
    }

    datafd = socket( AF_INET, SOCK_STREAM, 0 );
    if ( datafd < 0 ) {
	error( 425, "Can't open passive connection" );
	datafd = 0;
	return;
    }
    on = 1;
    if ( setsockopt( datafd, SOL_SOCKET, SO_REUSEADDR,
		     &on, sizeof(on) ) < 0 ) {
	error( 421, "setsockopt" );
	return;
    }

    dataconn = ctrlconn;
    if ( firstport && lastport )
	firstporttried = firstport + ( getpid() % (lastport-firstport+1) );
    else
	firstporttried = 0;

    p = firstporttried;;
    dataconn.sin_port = ntohs( p );
    while ( bind( datafd,
		  (struct sockaddr *)&dataconn, sizeof(dataconn) ) < 0 ) {
	if ( firstporttried ) {
	    p--;
	    if ( p < firstport )
		p = lastport;
	}
	if ( firstporttried == 0 || firstporttried == p ) {
	    if ( firstporttried )
		addreply( 0, "TCP ports %d to %d inclusive are all busy",
			  firstport, lastport );
	    error( 425, "Can't bind to socket" );
	    close( datafd );
	    datafd = 0;
	    return;
	}
	dataconn.sin_port = ntohs( p );
    }
    (void)listen( datafd, 1 );	/* maybe 0 on some unices? */

    fodder = sizeof( dataconn );
    if ( getsockname( datafd, (struct sockaddr *)&dataconn, &fodder ) < 0 ) {
	error( 425, "Can't getsockname( dataconn )" );
	close( datafd );
	datafd = 0;
	return;
    }
    a = ntohl( dataconn.sin_addr.s_addr );
    p = ntohs( (unsigned short int ) ( dataconn.sin_port ) );
    if ( useepsv )
	addreply( 229, "Extended Passive mode OK (|||%d|)", p );
    else
	addreply( 227, "Passive mode OK (%d,%d,%d,%d,%d,%d)",
		  (a >> 24) & 255, (a >> 16) & 255, (a >> 8) & 255, a & 255,
		  (p >> 8) & 255, p & 255 );
    passive = 1;
    return;
}


void doport( unsigned int a, unsigned int p )
{
    struct sockaddr_in dataconn;	/* his endpoint */
    int on;

    if ( datafd ) { /* for buggy clients saying PORT over and over */
	close( datafd );
	datafd = 0;
    }

    datafd = socket( AF_INET, SOCK_STREAM, 0 );
    if ( datafd < 0 ) {
	error( 425, "Can't make data socket" );
	datafd = 0;
	return;
    }
    on = 1;
    if ( setsockopt( datafd, SOL_SOCKET, SO_REUSEADDR,
		     &on, sizeof(on) ) < 0 ) {
	error( 421, "setsockopt" );
	return;
    }
    dataconn = ctrlconn;
    dataconn.sin_port = htons( (short ) 20 ); /* FTP data connection port */
    if ( bind( datafd, (struct sockaddr *)&dataconn, sizeof(dataconn) ) < 0 ) {
	error( -220, "bind" );
	close( datafd );
	datafd = 0;
	return;
    }

    if ( debug )
	addreply( 0, "My data connection endpoint is %s:%d",
		  inet_ntoa( *(struct in_addr *)&dataconn.sin_addr.s_addr ),
		  ntohs( dataconn.sin_port ) );

    peerdataport = p;

    if ( htonl( a ) != peer.sin_addr.s_addr ) {
	addreply( 425, "Will not open connection to %d.%d.%d.%d (only to %s)",
		  (a >> 24) & 255, (a >> 16) & 255, (a >> 8) & 255, a & 255,
		  inet_ntoa( peer.sin_addr ) );
	close( datafd );
	datafd = 0;
	return;
    }

    passive = 0;

    addreply( 200, "PORT command successful" );
    return;
}



int opendata( void )
{
    struct sockaddr_in dataconn;	/* his data connection endpoint */
    int fd;
    int fodder;

    if ( !datafd ) {
	error( 425, "No data connection" );
	return 0;
    }

    if ( passive ) {
	fd_set rs;
	struct timeval tv;

	FD_ZERO( &rs );
	FD_SET( datafd, &rs );
	tv.tv_sec = idletime;
	tv.tv_usec = 0;
	/* I suppose it would be better to listen for ABRT too... */
	if ( !select( datafd + 1, &rs, NULL, NULL, &tv ) ) {
	    addreply( 421,
		      "timeout (no connection for %d seconds)", idletime );
	    doreply();
	    exit( 23 );
	}
	fodder = sizeof( dataconn );
	fd = accept( datafd, (struct sockaddr *)&dataconn, &fodder );
	if ( fd < 0 ) {
	    error( 421, "accept failed" );
	    close( datafd );
	    datafd = 0;
	    return 0;
	}
	if ( !guest && dataconn.sin_addr.s_addr != peer.sin_addr.s_addr ) {
	    addreply( 425, "Connection must originate at %s (not %s)",
		      inet_ntoa( peer.sin_addr ),
		      inet_ntoa( dataconn.sin_addr ) );
	    close( datafd );
	    datafd = 0;
	    return 0;
	}
	addreply( 150, "Accepted data connection from %s:%d",
		  inet_ntoa( dataconn.sin_addr ),
		  ntohs((unsigned short int)dataconn.sin_port) );
    } else {
	dataconn.sin_addr.s_addr = peer.sin_addr.s_addr;
	dataconn.sin_port = htons( peerdataport );
	dataconn.sin_family = AF_INET;

	if (connect(datafd, (struct sockaddr *)&dataconn, sizeof(dataconn))) {
	    addreply( 425, "Could not open data connection to %s port %d: %s",
		      inet_ntoa( dataconn.sin_addr ), peerdataport,
		      strerror( errno ) );
	    close( datafd );
	    datafd = 0;
	    return 0;
	}
	fd = datafd;
	datafd = 0;
	addreply( 150, "Connecting to %s:%d",
		  inet_ntoa( dataconn.sin_addr ), peerdataport );
    }

    fodder = IPTOS_THROUGHPUT;
    if ( setsockopt( fd, SOL_IP, IP_TOS, (char *)&fodder, sizeof(int) ) < 0 )
	  syslog( LOG_WARNING, "setsockopt( IP_TOS ): %m" );

    fodder = window;
    if ( setsockopt( fd, SOL_SOCKET, SO_SNDBUF,
		     (char *)&fodder, sizeof(int) ) < 0 )
	syslog( LOG_WARNING, "setsockopt( SO_SNDBUF, %d ): %m", window );

    fodder = window;	/* not that important, but... */
    if ( setsockopt( fd, SOL_SOCKET, SO_RCVBUF,
		     (char *)&fodder, sizeof(int) ) < 0 )
	syslog( LOG_WARNING, "setsockopt( SO_RCVBUF, %d ): %m", window );

    return fd;
}


void dodele( const char *name )
{
    if ( guest )
	addreply( 550, "Anonymous users can not delete files." );
    else if ( unlink( name ) )
	addreply( 550, "Could not delete %s: %s", name, strerror( errno ) );
    else
	addreply( 250, "Deleted %s", name );
}


void doretr( const char *name )
{
    int c, f, o, s, skip;
    struct stat st;
    char *p, *buf;
    int left;
    struct timeval started, ended;
    double t;
    double speed;
    char speedstring[30];

    if ( !candownload ) {
	addreply( 550, "The load was %3.2f when you connected.  We do not "
		  "allow downloads\nby anonymous users when the load is "
		  "that high.  Uploads are always\nallowed.", load );
	return;
    }

    f = open( name, O_RDONLY );
    if ( f < 0 ) {
	char buffer[PATH_MAX + 40];
	snprintf( buffer, PATH_MAX+39, "Can't open %s", name );
	error( 550, buffer );
	return;
    }
    if ( fstat( f, &st ) ) {
	close( f );
	error( 451, "can't find file size" );
	return;
    }
    if ( restartat && ( restartat > st.st_size ) ) {
	addreply( 451, "Restart offset %d is too large for file size %d.\n"
		  "Restart offset reset to 0.",
		  restartat, st.st_size );
	return;
    }
    if ( !S_ISREG( st.st_mode ) ) {
	close( f );
	addreply( 450, "Not a regular file" );
	return;
    }
    if ( warez && ( st.st_uid == warez ) && guest ) {
	close( f );
	addreply( 550, "This file has been uploaded by an anonymous user.  "
		  "It has not\nyet been approved for downloading by "
		  "the site administrators.\n" );
	return;
    }

    c = opendata();
    if ( !c ) {
	close( f );
	return;
    }

    if ( restartat == st.st_size ) {
	/* some clients insist on doing this.  I can't imagine why. */
	addreply( 226,
		  "Nothing left to download.  Restart offset reset to 0." );
	close( f );
	close( c );
	return;
    }

    if ( (s = fcntl( c, F_GETFL, 0 ) ) < 0 ) {
	error( 451, "fcntl failed" );
	close( f );
	close( c );
	return;
    }
    s |= FNDELAY;
    fcntl( c, F_SETFL, s );

    if ( type == 1 ) {
	addreply( 0,
		  "NOTE: ASCII mode requested, but binary mode used" );
	if ( (time( 0 ) % 1000000 ) == 0 )
	    addreply( 0, "The computer is your friend.	Trust the computer" );
    }
    if ( st.st_size - restartat > 4096 )
	addreply( 0, "%.1f kbytes to download",
		  (st.st_size - restartat) / 1024.0 );

    doreply();

    (void)gettimeofday( &started, NULL );

    o = restartat & ~262143;
    skip = restartat - o;
    while ( o < st.st_size ) {
	left = st.st_size - o;
	if ( left > 262144 )
	    left = 262144;
	buf = mmap( 0, left, PROT_READ, MAP_FILE | MAP_SHARED, f, o );
	if ( buf == (char *)-1 ) {
	    error( 451, "mmap of file failed" );
	    close( f );
	    close( c );
	    return;
	}
	p = buf;
	o += left;
	s = left;
	while ( left > skip ) {
	    size_t w;

	    w = write( c, p+skip, (size_t) (left - skip) );
	    if ( (int ) w < 0 ) {
		if ( errno == EAGAIN ) {
		    /* wait idletime seconds for progress */
		    fd_set rs;
		    fd_set ws;
		    struct timeval tv;

		    FD_ZERO( &rs );
		    FD_ZERO( &ws );
		    FD_SET( 0, &rs );
		    FD_SET( c, &ws );
		    tv.tv_sec = idletime;
		    tv.tv_usec = 0;
		    select( c + 1, &rs, &ws, NULL, &tv );
		    if ( FD_ISSET( 0, &rs ) ) {
			/* we assume is is ABRT since nothing else is legal */
			addreply( 426, "Transfer aborted" );
			munmap( buf, s );
			close( f );
			close( c );
			return;
		    } else if ( !( FD_ISSET( c, &ws ) ) ) {
			/* client presumably gone away */
			syslog( LOG_INFO,
				"died: %d seconds without download progress",
				idletime );
			exit( 11 );
		    }
		    w = 0;
		} else {
		    error( 450, "Error during write to data connection" );
		    close( f );
		    close( c );
		    return;
		}
	    }
	    left -= w;
	    p += w;
	}
	skip = 0;
	munmap( buf, s );
    }

    (void)gettimeofday( &ended, NULL );
    t = ( ended.tv_sec + ended.tv_usec / 1000000.0 ) -
	( started.tv_sec + started.tv_usec / 1000000.0 );
    addreply( 226, "File written successfully" );
    if ( t && ( st.st_size - restartat ) > 2*window )
	speed = ( st.st_size - restartat - window ) / t;
    else
	speed = 0.0;
    addreply( 0, "%.3f seconds (measured by the server), %.2f %sb/s", t,
	      speed > 524288 ? speed / 1048576 : speed / 1024,
	      speed > 524288 ? "M" : "K" );
    close( f );
    close( c );

    downloaded = downloaded + st.st_size - restartat;

    if ( restartat ) {
	restartat = 0;
	addreply( 0, "Restart offset reset to 0." );
    }

    snprintf( speedstring, 29, " (%.2fKB/sec)", speed/1024 );
    syslog( LOG_INFO, "%s%s%s%s downloaded%s",
	    rd ? rd :  "",
	    *name == '/' ? "" : wd,
	    ( *name != '/' && ( !*wd || wd[strlen( wd ) - 1] != '/' ) )
	    ? "/" : "",
	    name,
	    speed > 0.1 ? speedstring : "" );
}


void dorest (const char *name)
{
    char *endptr;
    restartat = strtoul( name, &endptr, 10 );
    if ( *endptr ) {
	restartat = 0;
	addreply( 501, "RESTART needs numeric parameter.\n"
		  "Restart offset set to 0." );
    } else {
	syslog( LOG_NOTICE, "info: restart %d", restartat );
	addreply( 350,
		  "Restarting at %ld. Send STOR or RETR to initiate transfer.",
		  restartat );
    }
}



/* next two functions contributed by Patrick Michael Kane <modus@asimov.net> */
void domkd( const char *name )
{
    if ( guest )
	addreply( 550, "Sorry, anonymous users are not allowed to "
		  "make directories." );
    else if ( (mkdir( name, 0755 ) ) < 0 )
	error( 550, "Can't create directory" );
    else
	addreply( 257, "MKD command successful." );
}


void dormd( const char *name )
{
    if ( guest )
	addreply( 550, "Sorry, anonymous users are not allowed to "
		  "remove directories." );
    else if ( (rmdir( name ) ) < 0 )
	error( 550, "Can't remove directory" );
    else
	addreply( 250, "RMD command successful." );
}


void dostor( const char *name )
{
    int c, f;
    char *p;
    char buf[16384];
    int r;
    int filesize;
    struct statfs statfsbuf;
    struct stat st;
    // Added for ascii upload
    uint i,j;
    char cpy[16384];
    char *q;

    filesize = 0;

    if ( type < 1 ) {
	addreply( 503, "Only ASCII and binary modes are supported" );
	return;
    }

    if ( !stat( name, &st ) )  {
	if ( guest ) {
	    addreply( 553,
		      "Anonymous users may not overwrite existing files" );
	    return;
	}
    } else if ( errno != ENOENT ) {
	error( 553, "Can't check for file presence" );
	return;
    }
    f = open( name, O_CREAT | O_TRUNC | O_WRONLY, 0600 );
    if ( f < 0 ) {
	error( 553, "Can't open file" );
	return;
    }
    if ( restartat && lseek(f, restartat, SEEK_SET) < 0) {
	error (451, "can't seek" );
	return;
    }

    c = opendata();
    if ( !c ) {
	close( f );
	return;
    }
    doreply();

    do {
	/* wait idletime seconds for data to be available */
	fd_set rs;
	struct timeval tv;

	FD_ZERO( &rs );
	FD_SET( 0, &rs );
	FD_SET( c, &rs );
	tv.tv_sec = idletime;
	tv.tv_usec = 0;
	select( c + 1, &rs, NULL, NULL, &tv );
	if ( FD_ISSET( 0, &rs ) ) {
	    addreply( 0, "ABRT is the only legal command while uploading" );
	    addreply( 426, "Transfer aborted" );
	    close( f );
	    close( c );
	    addreply( 0, "%s %s", name,
		      unlink( name ) ? "partially uploaded" : "removed" );
	    return;
	} else if ( !( FD_ISSET( c, &rs ) ) ) {
	    /* client presumably gone away */
	    unlink( name );
	    syslog( LOG_INFO, "died: %d seconds without upload progress",
		    idletime );
	    exit( 20 );
	}
	r = read( c, &buf, 16384 );
	if ( r > 0 ) {
	    p = buf;

	    filesize += r;
	    while ( r ) {
		size_t w;

		if ( type == 1 ) {
		    int k = 0;
		    i = 0;
		    j = 0;
		    while ( i < (size_t) r ) {
			if ( p[i] == '\r' ) {
			    i++;
			    k++;
 			}
			cpy[j++] = buf[i++];
		    }
		    q = cpy;
		    r -= k;
		    w = write( f, q, (size_t) r );
		} else {
		    w = write( f, p, (size_t) r );
		}

		if ( (signed int)w < 0 ) {
		    error( -450, "Error during write to file" );
		    close( f );
		    close( c );
		    addreply( 450, "%s %s", name,
			      unlink(name)?"partially uploaded":"removed" );
		    return;
		}
		r -= w;
		p += w;
	    }
	    r = 1;
	} else if ( r < 0 ) {
	    error( -451, "Error during read from data connection" );
	    close( f );
	    close( c );
	    addreply( 451, "%s %s", name,
		      unlink( name ) ? "partially uploaded" : "removed" );
	    return;
	}
    } while ( r > 0 );

    fchmod( f, 0644 );
    addreply( 226, "File written successfully" );

    if ( fstatfs( f, &statfsbuf ) == 0 ) {
	double space;

	space = (double)statfsbuf.f_bsize * (double)statfsbuf.f_bavail;
	if ( space > 524288 )
	    addreply( 0, "%.1f Mbytes free disk space", space / 1048576 );
	else
	    addreply( 0, "%f Kbytes free disk space", space / 1024 );
    }
    close( f );
    close( c );
    uploaded += filesize;
    syslog( LOG_INFO, "%s%s%s%s uploaded",
	    rd ? rd :  "",
	    *name == '/' ? "" : wd,
	    ( *name != '/' && ( !*wd || wd[strlen( wd ) - 1] != '/' ) )
	    ? "/" : "",
	    name );
    if ( restartat ) {
	restartat = 0;
	addreply( 0, "Restart offset reset to 0." );
    }
}



void domdtm( const char *name )
{
    struct stat st;
    struct tm *t;

    if ( !name || !*name ) {
	addreply( 500, "Command not understood" );
    } else if ( lstat( name, &st ) ) {
	if ( debug )
	    addreply( 0, "arg is %s, wd is %s", name, wd );
	addreply( 550, "Unable to stat()" );
    } else if ( !S_ISREG( st.st_mode ) ) {
	addreply( 550, "Not a regular file" );
    } else {
	t = gmtime( (time_t * ) & st.st_mtime );
	if ( !t ) {
	    addreply( 550, "gmtime() returned NULL" );
	} else {
	    addreply( 213, "%04d%02d%02d%02d%02d%02d",
		     t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
		     t->tm_hour, t->tm_min, t->tm_sec );
	}
    }
    return;
}


void dosize( const char *name )
{
    struct stat st;

    if ( !name || !*name ) {
	addreply( 500, "Command not understood" );
    } else if ( lstat( name, &st ) ) {
	if ( debug )
	    addreply( 0, "arg is %s, wd is %s", name, wd );
	addreply( 550, "Unable to stat()" );
    } else if ( !S_ISREG( st.st_mode ) ) {
	addreply( 550, "Not a regular file" );
    } else {
	addreply( 213, "%ld", (long)st.st_size );
    }
    return;
}


void dotype( const char *arg )
{
    replycode = 200;	/* bloody awful hack */

    if ( !arg || !*arg ) {
	addreply( 501, "TYPE needs an argument\n"
		 "Only A(scii), I(mage) and L(ocal) are supported" );
    } else if ( tolower(*arg) == 'a' )
	type = 1;
    else if ( tolower(*arg) == 'i' )
	type = 2;
    else if ( tolower(*arg) == 'l' ) {
	if ( arg[1] == '8' ) {
	    type = 2;
	} else if ( isdigit( arg[1] ) ) {
	    addreply( 504, "Only 8-bit bytes are supported" );
	} else {
	    addreply( 0, "Byte size not specified" );
	    type = 2;
	}
    } else {
	addreply( 504, "Unknown TYPE: %s", arg );
    }

    addreply( 0, "TYPE is now %s", ( type > 1 ) ? "8-bit binary" : "ASCII" );
}


void dostru( const char *arg )
{
    if ( !arg || !*arg )
	addreply( 500, "No arguments\n"
		 "Not that it matters, only STRU F is supported" );
    else if ( strcasecmp( arg, "F" ) )
	addreply( 504, "STRU %s is not supported\nOnly F(ile) is supported",
		 arg );
    else
	addreply( 200, "F OK" );
}


void domode( const char *arg )
{
    if ( !arg || !*arg )
	addreply( 500, "No arguments\n"
		 "Not that it matters, only MODE S is supported" );
    else if ( strcasecmp( arg, "S" ) )
	addreply( 504, "MODE %s is not supported\n"
		 "Only S(tream) is supported", arg );
    else
	addreply( 200, "S OK" );
}


void dornfr( const char *name )
{
    struct stat st;
    if ( guest ) {
	addreply( 550,
		  "Sorry, anonymous users are not allowed to rename files." );
    } else if ( ( stat( name, &st ) ) == 0 ) {
	if ( renamefrom ) {
	    addreply( 0, "Aborting previous rename operation." );
	    (void) free( renamefrom );
	}
	renamefrom = strdup( name );
	addreply( 350, "RNFR accepted - file exists, ready for destination." );
    } else {
	addreply( 550, "File does not exist!" );
    }
    return;
}


/* rnto can return 550, which is not strictly allowed */

void dornto( const char *name )
{
    struct stat st;
    if ( guest )
	addreply( 550,
		  "Sorry, anonymous users are not allowed to rename files." );
    else if ( ( stat( name, &st ) ) == 0 )
	addreply( 550, "RENAME Failed - destination file already exists." );
    else if ( !renamefrom )
	addreply( 503, "Need RNFR before RNTO" );
    else if ( rename( renamefrom, name ) < 0 )
	addreply( 550, "Rename failed: %s", strerror( errno ) );
    else
	addreply( 250, "File renamed." );

    if ( renamefrom )
	(void) free( renamefrom );
    renamefrom = 0;
    return;
}


void error( int n, const char *msg )
{
    int e = errno;
    syslog( LOG_ERR, "%s: %m", msg );
    addreply( n, "%s: %s", msg, strerror( e ) );
}


void quit421( const char * message, int lineno )
{
    printf( "421 %s\r\n", message );
    fflush( stdout );
    syslog( LOG_ERR, "line %d: %s", lineno, message );
    exit( 1 );
}


int main( int argc, char **argv )
{
    int fodder;
    struct hostent * he;
    struct passwd * pw;
    FILE *f;
    double maxload;
    time_t tmt;
    struct tm *t;
    struct rusage ru;
    unsigned long maxusers;
    struct sigaction sa;
    int maxram;

    /* logging stuff.  use sigaction so they're not reset */
    sa.sa_handler = sighandler;
    sigemptyset( &sa.sa_mask );
    sa.sa_flags = SA_RESTART;
    (void)sigaction( SIGUSR1, &sa, NULL );
    (void)sigaction( SIGUSR2, &sa, NULL );
    /* we pretend urgent data doesn't exist */
    sa.sa_handler = SIG_IGN;
    (void)sigaction( SIGURG, &sa, NULL );

    maxload = 0.0;
    maxram = 1024;
    maxusers = 0;

    /* the first openlog will probably be overwritten by -f ten lines
       below, so don't put too much code between them. */

    openlog( "in.ftpd", LOG_CONS | LOG_PID, LOG_LOCAL2 );

    /* mmap in /var/adm/ftp/users and /var/adm/ftp/groups, for use by
       ls. do it before the chroot if ls is supposed to show the same
       stuff. */
    getnames();

    while ( (fodder = getopt( argc, argv, "ax:bc:df:m:p:r:su:" ) ) != -1 ) {
	if ( fodder == 'a' ) {
	    keeproot = 1;
	} else if ( fodder == 'f' ) {
	    int n;
	    n = 0;
	    while( facilitynames[n].c_name &&
		   strcasecmp( facilitynames[n].c_name, optarg ) )
		n++;
	    if ( facilitynames[n].c_name ) {
		closelog();
		openlog( "in.ftpd", LOG_CONS | LOG_PID, 
			 facilitynames[n].c_val );
	    } else {
		syslog( LOG_ERR, "Configuration error: "
			"Unknown facility name %s.", optarg );
	    }
	} else if ( fodder == 's' ) {
	    pw = getpwnam( "ftp" );
	    if ( pw != NULL )
		warez = pw->pw_uid;
	    else
		syslog( LOG_ERR, "Configuration error: "
			"can't find \"ftp\" uid" );
	} else if ( fodder == 'x' ) {
	    struct group * gr = getgrnam( optarg );
	    if ( gr != NULL )
		chroot_trustedgid = gr->gr_gid;
	    else
		syslog( LOG_ERR, "Configuration error: "
			"can't find group \"%s\" (for -x)", optarg );
	    /* but the ftpd can run in this case */
	    userchroot = 1;
        } else if ( fodder == 'd' ) {
	    if ( logging < 2 )
		logging++;
	} else if ( fodder == 'b' ) {
	    broken = 1;
	} else if ( fodder == 'c' ) {
	    char *nptr, *endptr;

	    nptr = optarg;
	    endptr = NULL;
	    maxusers = strtoul( nptr, &endptr, 0 );
	    if ( !nptr || !*nptr || !endptr || *endptr || !maxusers )
		syslog( LOG_ERR, "Illegal user limit: %s", optarg );
	} else if ( fodder == 'm' ) {
	    char *nptr, *endptr;

	    nptr = optarg;
	    endptr = NULL;
	    maxload = strtod( nptr, &endptr );
	    if ( !nptr || !*nptr || !endptr || *endptr || maxload <= 0.0 )
		syslog( LOG_ERR, "Illegal load limit: %s", optarg );
	} else if ( fodder == 'p' ) {
	    int ret;

	    ret = sscanf(optarg, "%d:%d", &firstport, &lastport);
	    if ( ret != 2 || firstport < 1024 || lastport > 65535 ||
		 lastport <= firstport )
		syslog( LOG_ERR, "Illegal port range: %s", optarg );
	} else if ( fodder == 'r' ) {
	    char *nptr, *endptr;

	    nptr = optarg;
	    endptr = NULL;
	    maxram = strtod( nptr, &endptr );
	    if ( !nptr || !*nptr || !endptr || *endptr || maxload <= 0.0 )
		syslog( LOG_ERR, "Illegal RAM size limit: %s", optarg );
	} else if ( fodder == 'u' ) {
	    char *nptr, *endptr;
	    long tmp;

	    nptr = optarg;
	    endptr = NULL;
	    tmp = strtol( nptr, &endptr, 10 );
	    if ( !nptr || !*nptr || !endptr || *endptr || 
		 tmp > 65535 || tmp < 0 ) {
		/* have to quit in this case - anything else might be
                   a security problem */
		printf( "421 Configuration error: Illegal uid limit: %s\r\n",
			optarg );
		syslog( LOG_ERR, "Illegal uid limit: %s", optarg );
		sleep( 1 );
		exit( 16 );
	    }
	    useruid = (uid_t) tmp;
	}
    }

    if ( firstport || maxusers ) {
	unsigned int users;
	if ( firstport ) {
	    unsigned int portmax;
	    portmax = (lastport-firstport+1)/2;
	    if ( !maxusers || maxusers > portmax )
		maxusers = portmax; /* ... so we don't run out of ports */
	}

	users = daemons();
	if ( users > maxusers ) {
	    printf( "421 %lu users (the maximum) are already logged in\r\n",
		    maxusers );
	    sleep( 1 );
	    exit( 5 );
	}
	addreply( 0, "You are user number %d of %d allowed.",
		  users, maxusers );
    }

    if ( maxram ) {
	struct rlimit scratch;
	scratch.rlim_cur = scratch.rlim_max = 1024 * maxram;
	setrlimit( RLIMIT_DATA, &scratch );
	setrlimit( RLIMIT_STACK, &scratch );
	addreply( 0, "Setting memory limit to %d+%dkbytes", maxram, maxram );
    }

    load = -1.0;
    if ( (f = fopen( "/proc/loadavg", "r" ) ) != NULL &&
	 fscanf( f, "%lf", &load ) == 1 )
	fclose( f );

    fodder = sizeof(struct sockaddr_in);

    if ( getsockname( 0, (struct sockaddr *)&ctrlconn, &fodder ) ) {
	printf( "421 Cannot getsockname( STDIN ), errno=%d\r\n", errno );
	syslog( LOG_ERR, "Cannot getsockname( STDIN ): %s", strerror(errno) );
	exit( 3 );
    }

    loggedin = 0;

    if ( getpeername( 0, (struct sockaddr *)&peer, &fodder ) ) {
	printf( "421 Cannot getpeername( STDIN ), errno=%d\r\n", errno );
	syslog( LOG_ERR, "Cannot getpeername( STDIN ): %s", strerror(errno) );
	sleep( 1 );
	exit( 9 );
    }
    syslog( LOG_INFO, "connection from %s", inet_ntoa( peer.sin_addr ) );

    he = gethostbyaddr( (char *)&ctrlconn.sin_addr.s_addr,
			sizeof(ctrlconn.sin_addr.s_addr),
			AF_INET );

    /* if you want authenticated sites that don't use /etc/passed,
       this is a nice place to hack.  the below is an example of how
       it can be done, using SITEDIR/etc/passwd */

#if 0
#define SITENAME "myleetsite.troll.no"
#define SITEDIR "/local/myleetsite"
    if ( !strcasecmp( SITENAME, he->h_name ) ) {
	if ( chroot( SITEDIR ) ||
	     chdir( "/" ) ) {
	    printf( "421 Sorry, " SITENAME " is down\r\n" );
	    syslog( LOG_INFO, "Unable to cage in " SITENAME " user" );
	    fflush( stdout );
	    sleep( 1 );
	    exit( 20 );
	}
	/* it works and we've chrooted, so output the banner and go on,
	   using SITEDIR/etc/passwd for authentication */
	dobanner();
    }
#endif

    if ( he && he->h_name ) {
	char name[PATH_MAX];

	if ( snprintf( name, PATH_MAX, "/var/adm/ftp/%s/.", he->h_name ) < 0 ){
	    syslog( LOG_ERR, "host name far too long for %s",
		    inet_ntoa( ctrlconn.sin_addr ) );
	    exit( 15 );
	}
	if ( !chdir( name ) ) {
	    int l = strlen( he->h_name ) + 3;
	    rd = malloc( l );
	    /* it'd be much better with a separate name for "ftp" here */
	    pw = getpwnam( "ftp" );
	    if ( !rd || !pw ||
		 setregid( pw->pw_gid, pw->pw_gid ) ||
		 initgroups( pw->pw_name, pw->pw_gid ) ||
		 chroot( name ) ||
		 chdir( "/" ) )
		quit421( "Unable to cage in anonymous user", __LINE__ );
	    snprintf( rd, l, "%s:", he->h_name );
	    if ( keeproot )
		setfsuid( pw->pw_uid );
	    else
		setreuid( pw->pw_uid, pw->pw_uid );
	    dobanner();
	    loggedin = guest = 1;
	    syslog( LOG_INFO, "logged in guest of %s", he->h_name );
	}
	cpwd = strdup( "*" );
    }

    chdir( "/" );
    strcpy( wd, "/" );

    fodder = IPTOS_LOWDELAY;
    if ( setsockopt( 0, SOL_IP, IP_TOS, (char *)&fodder, sizeof(int) ) < 0 )
	syslog( LOG_WARNING, "setsockopt ( IP_TOS ): %m" );

    fodder = 1;
    if ( setsockopt( 0, SOL_SOCKET, SO_OOBINLINE,
		     (char *)&fodder, sizeof(int) ) < 0 )
	syslog( LOG_WARNING, "setsockopt: %m" );

    tmt = time( NULL );
    t = localtime( (time_t *) &tmt );
    if ( t != 0 && load >= 0.0 )
	addreply( 220,
		  "Local time is now %02d:%02d and the load is %3.2f.",
		  t->tm_hour, t->tm_min, load );
    else
	syslog( LOG_ERR, "unable to read load average or current time" );

    if ( loggedin )
	addreply( 220,
		  "Only anonymous FTP is allowed at %s.", he->h_name );

    addreply( 220, "You will be disconnected after %d seconds of inactivity.",
	      idletime );

    candownload = maxload <= 0.0 || load < maxload;

    parser();

    if ( getrusage( RUSAGE_SELF, &ru ) == 0 ) {
	unsigned long s, u;

	u = ( ru.ru_utime.tv_usec + ru.ru_stime.tv_usec + 500 ) / 1000;
	s = ru.ru_utime.tv_sec + ru.ru_stime.tv_sec;
	if ( u > 999 ) {
	    u -= 1000;
	    s++;
	}
	addreply( 0, "CPU time spent on you: %ld.%03ld seconds.", s, u );
    }
    doreply();
    sleep( 1 );
    exit( 0 );
}
