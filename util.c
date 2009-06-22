/* util.c */

#include "util.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

void
die( const char *msg, ... ) {
  va_list ap;
  va_start( ap, msg );
  fprintf( stderr, "Stopping: " );
  vfprintf( stderr, msg, ap );
  va_end( ap );
  exit( 1 );
}

void
noerr( int rc ) {
  if ( rc != 0 )
    die( "error %d", rc );
}

/* vim:ts=2:sw=2:sts=2:et:ft=c 
 */
