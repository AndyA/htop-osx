/* util.c */

#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <mach/kern_return.h>

void
noerr( kern_return_t rc ) {
  if ( rc != 0 ) {
    fprintf( stderr, "Oops: %d\n", rc );
    exit( 1 );
  }
}

/* vim:ts=2:sw=2:sts=2:et:ft=c 
 */
