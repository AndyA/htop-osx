/*
htop - ProcessList.c
(C) 2004,2005 Hisham H. Muhammad
Released under the GNU GPL, see the COPYING file
in the source distribution for its full text.
*/

/* Darwin reference:
 *
 * http://web.mit.edu/darwin/src/modules/xnu/osfmk/man/
 *
 */

#ifndef CONFIG_H
#define CONFIG_H
#include "config.h"
#endif

#include "ProcessList.h"
#include "Process.h"
#include "Vector.h"
#include "UsersTable.h"
#include "Hashtable.h"
#include "String.h"

#include <dirent.h>
#include <mach/host_info.h>
#include <mach/mach_host.h>
#include <mach/mach_init.h>
#include <mach/mach_interface.h>
#include <mach/mach_port.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
#include <mach/machine.h>
#include <mach/processor_info.h>
#include <mach/shared_memory_server.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <mach/time_value.h>
#include <mach/vm_map.h>
#include <sys/proc.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "util.h"
#include <assert.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE ( sysconf(_SC_PAGESIZE) )
#endif

static ProcessField defaultHeaders[] =
    { PID, USER, PRIORITY, NICE, M_SIZE, M_RESIDENT, M_SHARE, STATE,
  PERCENT_CPU, PERCENT_MEM, TIME, COMM, 0
};

static inline void
ProcessList_allocatePerProcessorBuffers( ProcessList * this, int procs ) {
  unsigned long long int **bufferPtr = &( this->totalTime );
  unsigned long long int *buffer = calloc( procs * PER_PROCESSOR_FIELDS,
                                           sizeof( unsigned long long
                                                   int ) );
  for ( int i = 0; i < PER_PROCESSOR_FIELDS; i++ ) {
    *bufferPtr = buffer;
    bufferPtr++;
    buffer += procs;
  }
}

ProcessList *
ProcessList_new( UsersTable * usersTable ) {
  ProcessList *this;
  host_basic_info_data_t hostInfo;
  mach_msg_type_number_t infoCount;

  this = malloc( sizeof( ProcessList ) );
  this->processes =
      Vector_new( PROCESS_CLASS, true, DEFAULT_SIZE, Process_compare );
  this->processTable = Hashtable_new( 70, false );
  assert( Hashtable_count( this->processTable ) ==
          Vector_count( this->processes ) );
  this->prototype = Process_new( this );
  this->usersTable = usersTable;

  /* tree-view auxiliary buffers */
  this->processes2 =
      Vector_new( PROCESS_CLASS, true, DEFAULT_SIZE, Process_compare );

#ifdef DEBUG_PROC
  this->traceFile = fopen( "/tmp/htop-proc-trace", "w" );
#endif

  infoCount = HOST_BASIC_INFO_COUNT;
  noerr( host_info( mach_host_self(  ), HOST_BASIC_INFO,
                    ( host_info_t ) & hostInfo, &infoCount ) );
  this->processorCount = hostInfo.avail_cpus;
  this->totalMem = hostInfo.max_mem / 1024;

  host_page_size( mach_host_self(  ), &this->pageSize );

  /* TODO not sure we need the +1 here */
  ProcessList_allocatePerProcessorBuffers( this, hostInfo.avail_cpus + 1 );

  for ( int i = 0; i < hostInfo.avail_cpus + 1; i++ ) {
    this->totalTime[i] = 1;
    this->totalPeriod[i] = 1;
  }

  this->fields = calloc( sizeof( ProcessField ), LAST_PROCESSFIELD + 1 );
  // TODO: turn 'fields' into a Vector,
  // (and ProcessFields into proper objects).
  for ( int i = 0; defaultHeaders[i]; i++ ) {
    this->fields[i] = defaultHeaders[i];
  }
  this->sortKey = PERCENT_CPU;
  this->direction = 1;
  this->hideThreads = false;
  this->shadowOtherUsers = false;
  this->hideKernelThreads = false;
  this->hideUserlandThreads = false;
  this->treeView = false;
  this->highlightBaseName = false;
  this->highlightMegabytes = false;
  this->detailedCPUTime = false;

  return this;
}

void
ProcessList_delete( ProcessList * this ) {
  Hashtable_delete( this->processTable );
  Vector_delete( this->processes );
  Vector_delete( this->processes2 );
  Process_delete( ( Object * ) this->prototype );

  // Free first entry only;
  // other fields are offsets of the same buffer
  free( this->totalTime );

#ifdef DEBUG_PROC
  fclose( this->traceFile );
#endif

  free( this->fields );
/*   free(this);*/
}

void
ProcessList_invertSortOrder( ProcessList * this ) {
  if ( this->direction == 1 )
    this->direction = -1;
  else
    this->direction = 1;
}

RichString
ProcessList_printHeader( ProcessList * this ) {
  RichString out;
  RichString_initVal( out );
  ProcessField *fields = this->fields;
  for ( int i = 0; fields[i]; i++ ) {
    char *field = Process_fieldTitles[fields[i]];
    if ( this->sortKey == fields[i] )
      RichString_append( &out, CRT_colors[PANEL_HIGHLIGHT_FOCUS], field );
    else
      RichString_append( &out, CRT_colors[PANEL_HEADER_FOCUS], field );
  }
  return out;
}

static void
ProcessList_add( ProcessList * this, Process * p ) {
  assert( Vector_indexOf( this->processes, p, Process_pidCompare ) == -1 );
  assert( Hashtable_get( this->processTable, p->pid ) == NULL );
  Vector_add( this->processes, p );
  Hashtable_put( this->processTable, p->pid, p );
  assert( Vector_indexOf( this->processes, p, Process_pidCompare ) != -1 );
  assert( Hashtable_get( this->processTable, p->pid ) != NULL );
  assert( Hashtable_count( this->processTable ) ==
          Vector_count( this->processes ) );
}

static void
ProcessList_remove( ProcessList * this, Process * p ) {
  assert( Vector_indexOf( this->processes, p, Process_pidCompare ) != -1 );
  assert( Hashtable_get( this->processTable, p->pid ) != NULL );
  Process *pp = Hashtable_remove( this->processTable, p->pid );
  assert( pp == p );
  ( void ) pp;
  unsigned int pid = p->pid;
  int index = Vector_indexOf( this->processes, p, Process_pidCompare );
  assert( index != -1 );
  Vector_remove( this->processes, index );
  assert( Hashtable_get( this->processTable, pid ) == NULL );
  ( void ) pid;
  assert( Hashtable_count( this->processTable ) ==
          Vector_count( this->processes ) );
}

Process *
ProcessList_get( ProcessList * this, int index ) {
  return ( Process * ) ( Vector_get( this->processes, index ) );
}

int
ProcessList_size( ProcessList * this ) {
  return ( Vector_size( this->processes ) );
}

static void
ProcessList_buildTree( ProcessList * this, int pid, int level, int indent,
                       int direction ) {
  Vector *children =
      Vector_new( PROCESS_CLASS, false, DEFAULT_SIZE, Process_compare );

  for ( int i = Vector_size( this->processes ) - 1; i >= 0; i-- ) {
    Process *process = ( Process * ) ( Vector_get( this->processes, i ) );
    if ( process->tgid == pid
         || ( process->tgid == process->pid && process->ppid == pid ) ) {
      Process *process =
          ( Process * ) ( Vector_take( this->processes, i ) );
      Vector_add( children, process );
    }
  }
  int size = Vector_size( children );
  for ( int i = 0; i < size; i++ ) {
    Process *process = ( Process * ) ( Vector_get( children, i ) );
    int s = this->processes2->items;
    if ( direction == 1 )
      Vector_add( this->processes2, process );
    else
      Vector_insert( this->processes2, 0, process );
    assert( this->processes2->items == s + 1 );
    ( void ) s;
    int nextIndent = indent;
    if ( i < size - 1 )
      nextIndent = indent | ( 1 << level );
    ProcessList_buildTree( this, process->pid, level + 1, nextIndent,
                           direction );
    process->indent = indent | ( 1 << level );
  }
  Vector_delete( children );
}

void
ProcessList_sort( ProcessList * this ) {
  if ( !this->treeView ) {
    Vector_sort( this->processes );
  }
  else {
    // Save settings
    int direction = this->direction;
    int sortKey = this->sortKey;
    // Sort by PID
    this->sortKey = PID;
    this->direction = 1;
    Vector_sort( this->processes );
    // Restore settings
    this->sortKey = sortKey;
    this->direction = direction;
    // Take PID 1 as root and add to the new listing
    int vsize = Vector_size( this->processes );
    Process *init = ( Process * ) ( Vector_take( this->processes, 0 ) );
    // This assertion crashes on hardened kernels.
    // I wonder how well tree view works on those systems.
    // assert(init->pid == 1);
    init->indent = 0;
    Vector_add( this->processes2, init );
    // Recursively empty list
    ProcessList_buildTree( this, init->pid, 0, 0, direction );
    // Add leftovers
    while ( Vector_size( this->processes ) ) {
      Process *p = ( Process * ) ( Vector_take( this->processes, 0 ) );
      p->indent = 0;
      Vector_add( this->processes2, p );
      ProcessList_buildTree( this, p->pid, 0, 0, direction );
    }
    assert( Vector_size( this->processes2 ) == vsize );
    ( void ) vsize;
    assert( Vector_size( this->processes ) == 0 );
    // Swap listings around
    Vector *t = this->processes;
    this->processes = this->processes2;
    this->processes2 = t;
  }
}

static int
ProcessList_machStateOrder( int s, long sleep_time ) {
  switch ( s ) {
  case TH_STATE_RUNNING:
    return 1;
  case TH_STATE_UNINTERRUPTIBLE:
    return 2;
  case TH_STATE_WAITING:
    return ( sleep_time > 20 ) ? 4 : 3;
  case TH_STATE_STOPPED:
    return 5;
  case TH_STATE_HALTED:
    return 6;
  default:
    return 7;
  }
}

static int
ProcessList_schedInfo( KINFO * ki, thread_port_t thread, policy_t pol,
                       void *buf ) {
  unsigned int count;
  int ret = KERN_FAILURE;

  switch ( pol ) {

  case POLICY_TIMESHARE:
    count = POLICY_TIMESHARE_INFO_COUNT;
    ret = thread_info( thread, THREAD_SCHED_TIMESHARE_INFO,
                       ( thread_info_t ) buf, &count );
    if ( ( ret == KERN_SUCCESS )
         && ( ki->curpri <
              ( ( ( struct policy_timeshare_info * ) buf )->
                cur_priority ) ) )
      ki->curpri =
          ( ( struct policy_timeshare_info * ) buf )->cur_priority;
    break;

  case POLICY_FIFO:
    count = POLICY_FIFO_INFO_COUNT;
    ret = thread_info( thread, THREAD_SCHED_FIFO_INFO, buf, &count );
    if ( ( ret == KERN_SUCCESS )
         && ( ki->curpri <
              ( ( ( struct policy_fifo_info * ) buf )->base_priority ) ) )
      ki->curpri = ( ( struct policy_fifo_info * ) buf )->base_priority;
    break;

  case POLICY_RR:
    count = POLICY_RR_INFO_COUNT;
    ret = thread_info( thread, THREAD_SCHED_RR_INFO, buf, &count );
    if ( ( ret == KERN_SUCCESS )
         && ( ki->curpri <
              ( ( ( struct policy_rr_info * ) buf )->base_priority ) ) )
      ki->curpri = ( ( struct policy_rr_info * ) buf )->base_priority;
    break;
  }
  return ret;
}

static int
ProcessList_getTaskInfo( KINFO * ki ) {
  kern_return_t error;
  unsigned int info_count = TASK_BASIC_INFO_COUNT;
  unsigned int thread_info_count = THREAD_BASIC_INFO_COUNT;
  pid_t pid;
  int j, err = 0;

  pid = KI_PROC( ki )->p_pid;
  if ( task_for_pid( mach_task_self(  ), pid, &ki->task ) != KERN_SUCCESS ) {
    return 1;
  }
  info_count = TASK_BASIC_INFO_COUNT;
  error = task_info( ki->task, TASK_BASIC_INFO,
                     ( task_info_t ) & ki->tasks_info, &info_count );

  if ( error != KERN_SUCCESS ) {
    ki->invalid_tinfo = 1;
    return 1;
  }

  {
    vm_region_basic_info_data_64_t b_info;
    vm_address_t address = GLOBAL_SHARED_TEXT_SEGMENT;
    vm_size_t size;
    mach_port_t object_name;

    /*
     * try to determine if this task has the split libraries
     * mapped in... if so, adjust its virtual size down by
     * the 2 segments that are used for split libraries
     */
    info_count = VM_REGION_BASIC_INFO_COUNT_64;
    error = vm_region_64( ki->task, &address, &size, VM_REGION_BASIC_INFO,
                          ( vm_region_info_t ) & b_info, &info_count,
                          &object_name );
    if ( error == KERN_SUCCESS ) {
      if ( b_info.reserved && size == ( SHARED_TEXT_REGION_SIZE ) &&
           ki->tasks_info.virtual_size >
           ( SHARED_TEXT_REGION_SIZE + SHARED_DATA_REGION_SIZE ) )
        ki->tasks_info.virtual_size -=
            ( SHARED_TEXT_REGION_SIZE + SHARED_DATA_REGION_SIZE );
    }
  }

  {
    ki->shared = 0;
    ki->swapped_pages = 0;

    // This works but is far too slow to enable. Need a better way.
#if 0

    vm_address_t address;
    mach_port_t object_name;
    vm_region_extended_info_data_t info;
    vm_region_basic_info_data_64_t b_info;
    vm_size_t size;

    for ( address = 0;; address += size ) {
      info_count = VM_REGION_EXTENDED_INFO_COUNT;
      if ( vm_region
           ( ki->task, &address, &size, VM_REGION_EXTENDED_INFO,
             ( vm_region_extended_info_t ) & info, &info_count,
             &object_name ) != KERN_SUCCESS )
        break;

      ki->swapped_pages += info.pages_swapped_out;

      info_count = VM_REGION_BASIC_INFO_COUNT_64;
      if ( vm_region_64( ki->task, &address, &size, VM_REGION_BASIC_INFO,
                         ( vm_region_info_t ) & b_info, &info_count,
                         &object_name ) != KERN_SUCCESS )
        break;

      if ( b_info.shared )
        ki->shared += size;
    }
#endif
  }

  info_count = TASK_THREAD_TIMES_INFO_COUNT;
  error = task_info( ki->task, TASK_THREAD_TIMES_INFO,
                     ( task_info_t ) & ki->times, &info_count );
  if ( error != KERN_SUCCESS ) {
    ki->invalid_tinfo = 1;
    return 1;
  }

  switch ( ki->tasks_info.policy ) {

  case POLICY_TIMESHARE:
    info_count = POLICY_TIMESHARE_INFO_COUNT;
    error =
        task_info( ki->task, TASK_SCHED_TIMESHARE_INFO,
                   ( task_info_t ) & ki->schedinfo.tshare, &info_count );
    if ( error != KERN_SUCCESS ) {
      ki->invalid_tinfo = 1;
      return 1;
    }

    ki->curpri = ki->schedinfo.tshare.cur_priority;
    ki->basepri = ki->schedinfo.tshare.base_priority;
    break;

  case POLICY_RR:
    info_count = POLICY_RR_INFO_COUNT;
    error =
        task_info( ki->task, TASK_SCHED_RR_INFO,
                   ( task_info_t ) & ki->schedinfo.rr, &info_count );
    if ( error != KERN_SUCCESS ) {
      ki->invalid_tinfo = 1;
      return 1;
    }

    ki->curpri = ki->schedinfo.rr.base_priority;
    ki->basepri = ki->schedinfo.rr.base_priority;
    break;

  case POLICY_FIFO:
    info_count = POLICY_FIFO_INFO_COUNT;
    error =
        task_info( ki->task, TASK_SCHED_FIFO_INFO,
                   ( task_info_t ) & ki->schedinfo.fifo, &info_count );
    if ( error != KERN_SUCCESS ) {
      ki->invalid_tinfo = 1;
      return 1;
    }

    ki->curpri = ki->schedinfo.fifo.base_priority;
    ki->basepri = ki->schedinfo.fifo.base_priority;
    break;
  }

  ki->invalid_tinfo = 0;

  ki->cpu_usage = 0;
  error = task_threads( ki->task, &ki->thread_list, &ki->thread_count );
  if ( error != KERN_SUCCESS ) {
    mach_port_deallocate( mach_task_self(  ), ki->task );
    return 1;
  }
  err = 0;
  ki->state = STATE_MAX;
  //ki->curpri = 255;
  //ki->basepri = 255;
  ki->swapped = 1;
  ki->thval = malloc( ki->thread_count * sizeof( struct thread_values ) );
  if ( ki->thval != NULL ) {
    for ( j = 0; j < ki->thread_count; j++ ) {
      int tstate;
      thread_info_count = THREAD_BASIC_INFO_COUNT;
      error = thread_info( ki->thread_list[j], THREAD_BASIC_INFO,
                           ( thread_info_t ) & ki->thval[j].tb,
                           &thread_info_count );
      if ( error != KERN_SUCCESS ) {
        err = 1;
      }
      error = ProcessList_schedInfo( ki, ki->thread_list[j],
                                     ki->thval[j].tb.policy,
                                     &ki->thval[j].schedinfo );
      if ( error != KERN_SUCCESS ) {
        err = 1;
      }
      ki->cpu_usage += ki->thval[j].tb.cpu_usage;
      tstate = ProcessList_machStateOrder( ki->thval[j].tb.run_state,
                                           ki->thval[j].tb.sleep_time );
      if ( tstate < ki->state )
        ki->state = tstate;
      if ( ( ki->thval[j].tb.flags & TH_FLAGS_SWAPPED ) == 0 )
        ki->swapped = 0;
      mach_port_deallocate( mach_task_self(  ), ki->thread_list[j] );
    }
    free( ki->thval );
    ki->thval = NULL;
  }
  ki->invalid_thinfo = err;
  /* Deallocate the list of threads. */
  error = vm_deallocate( mach_task_self(  ),
                         ( vm_address_t ) ( ki->thread_list ),
                         sizeof( thread_port_array_t ) *
                         ki->thread_count );
  if ( error != KERN_SUCCESS ) {
  }

  mach_port_deallocate( mach_task_self(  ), ki->task );
  return 0;
}

static void
ProcessList_getCmdLine( KINFO * k, char *command_name, size_t bufsize,
                        int *cmdlen, int eflg, int show_args ) {
  int mib[3], argmax, nargs, c = 0;
  size_t size;
  char *procargs, *sp, *np, *cp;
/*  Made into a command argument. -- TRW
 *	extern int	eflg;
 */

  /* Get the maximum process arguments size. */
  mib[0] = CTL_KERN;
  mib[1] = KERN_ARGMAX;

  size = sizeof( argmax );
  if ( sysctl( mib, 2, &argmax, &size, NULL, 0 ) == -1 ) {
    goto ERROR_A;
  }

  /* Allocate space for the arguments. */
  procargs = ( char * ) malloc( argmax );
  if ( procargs == NULL ) {
    goto ERROR_A;
  }

  /*
   * Make a sysctl() call to get the raw argument space of the process.
   * The layout is documented in start.s, which is part of the Csu
   * project.  In summary, it looks like:
   *
   * /---------------\ 0x00000000
   * :               :
   * :               :
   * |---------------|
   * | argc          |
   * |---------------|
   * | arg[0]        |
   * |---------------|
   * :               :
   * :               :
   * |---------------|
   * | arg[argc - 1] |
   * |---------------|
   * | 0             |
   * |---------------|
   * | env[0]        |
   * |---------------|
   * :               :
   * :               :
   * |---------------|
   * | env[n]        |
   * |---------------|
   * | 0             |
   * |---------------| <-- Beginning of data returned by sysctl() is here.
   * | argc          |
   * |---------------|
   * | exec_path     |
   * |:::::::::::::::|
   * |               |
   * | String area.  |
   * |               |
   * |---------------| <-- Top of stack.
   * :               :
   * :               :
   * \---------------/ 0xffffffff
   */
  mib[0] = CTL_KERN;
  mib[1] = KERN_PROCARGS2;
  mib[2] = KI_PROC( k )->p_pid;

  size = ( size_t ) argmax;
  if ( sysctl( mib, 3, procargs, &size, NULL, 0 ) == -1 ) {
    goto ERROR_B;
  }

  memcpy( &nargs, procargs, sizeof( nargs ) );
  cp = procargs + sizeof( nargs );

  /* Skip the saved exec_path. */
  for ( ; cp < &procargs[size]; cp++ ) {
    if ( *cp == '\0' ) {
      /* End of exec_path reached. */
      break;
    }
  }
  if ( cp == &procargs[size] ) {
    goto ERROR_B;
  }

  /* Skip trailing '\0' characters. */
  for ( ; cp < &procargs[size]; cp++ ) {
    if ( *cp != '\0' ) {
      /* Beginning of first argument reached. */
      break;
    }
  }
  if ( cp == &procargs[size] ) {
    goto ERROR_B;
  }
  /* Save where the argv[0] string starts. */
  sp = cp;

  /*
   * Iterate through the '\0'-terminated strings and convert '\0' to ' '
   * until a string is found that has a '=' character in it (or there are
   * no more strings in procargs).  There is no way to deterministically
   * know where the command arguments end and the environment strings
   * start, which is why the '=' character is searched for as a heuristic.
   */
  for ( np = NULL; c < nargs && cp < &procargs[size]; cp++ ) {
    if ( *cp == '\0' ) {
      c++;
      if ( np != NULL ) {
        /* Convert previous '\0'. */
        *np = ' ';
      }
      /* Note location of current '\0'. */
      np = cp;

      if ( !show_args ) {
        /*
         * Don't convert '\0' characters to ' '.
         * However, we needed to know that the
         * command name was terminated, which we
         * now know.
         */
        break;
      }
    }
  }

  /*
   * If eflg is non-zero, continue converting '\0' characters to ' '
   * characters until no more strings that look like environment settings
   * follow.
   */
  if ( ( eflg != 0 )
       && ( ( getuid(  ) == 0 )
            || ( KI_EPROC( k )->e_pcred.p_ruid == getuid(  ) ) ) ) {
    for ( ; cp < &procargs[size]; cp++ ) {
      if ( *cp == '\0' ) {
        if ( np != NULL ) {
          if ( &np[1] == cp ) {
            /*
             * Two '\0' characters in a row.
             * This should normally only
             * happen after all the strings
             * have been seen, but in any
             * case, stop parsing.
             */
            break;
          }
          /* Convert previous '\0'. */
          *np = ' ';
        }
        /* Note location of current '\0'. */
        np = cp;
      }
    }
  }

  /*
   * sp points to the beginning of the arguments/environment string, and
   * np should point to the '\0' terminator for the string.
   */
  if ( np == NULL || np == sp ) {
    /* Empty or unterminated string. */
    goto ERROR_B;
  }

  /* Make a copy of the string. */
  *cmdlen = snprintf( command_name, bufsize, "%s", sp );

  /* Clean up. */
  free( procargs );
  return;

ERROR_B:
  free( procargs );
ERROR_A:
  *cmdlen =
      snprintf( command_name, bufsize, "(%s)", KI_PROC( k )->p_comm );
}

static int
ProcessList_decodeState( int st ) {
  switch ( st ) {
  case SIDL:
    return 'C';
  case SRUN:
    return 'R';
  case SSLEEP:
    return 'S';
  case SSTOP:
    return 'T';
  case SZOMB:
    return 'Z';
  default:
    return '?';
  }
}

static bool
ProcessList_getSwap( ProcessList * this ) {
  struct xsw_usage swap;
  size_t bufSize = 0;
  int mib[2] = { CTL_VM, VM_SWAPUSAGE };

  if ( sysctl( mib, 2, NULL, &bufSize, NULL, 0 ) < 0 )
    die( "Failure calling sysctl" );

  if ( sysctl( mib, 2, &swap, &bufSize, NULL, 0 ) < 0 )
    die( "Failure calling sysctl" );

  this->totalSwap = swap.xsu_total / 1024;
  this->freeSwap = swap.xsu_avail / 1024;
  this->usedSwap = swap.xsu_used / 1024;
}


static bool
ProcessList_getProcesses( ProcessList * this, float period ) {
  struct kinfo_proc *kprocbuf = NULL;
  size_t bufSize = 0;
  int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };

  Process *prototype = this->prototype;

  if ( sysctl( mib, 4, NULL, &bufSize, NULL, 0 ) < 0 )
    die( "Failure calling sysctl" );

  if ( ( kprocbuf = ( struct kinfo_proc * ) malloc( bufSize ) ) == NULL )
    die( "Memory allocation failure" );

  if ( sysctl( mib, 4, kprocbuf, &bufSize, NULL, 0 ) < 0 )
    die( "Failure calling sysctl" );

  this->totalTasks = bufSize / sizeof( struct kinfo_proc );

  for ( int i = this->totalTasks - 1; i >= 0; i-- ) {
    struct kinfo_proc *kp = &kprocbuf[i];
    struct extern_proc *p;
    struct eproc *e;
    KINFO kinfo;
    memset( &kinfo, 0, sizeof( kinfo ) );
    KINFO *ki = &kinfo;
    char command_name[512];
    int cmdlen, pid;
    time_value_t total_time, system_time, user_time;

    ki->ki_p = kp;

    ProcessList_getTaskInfo( ki );

    p = KI_PROC( ki );
    e = KI_EPROC( ki );

    pid = p->p_pid;
    if ( pid == 0 )
      continue;

    Process *process = NULL;
    Process *existingProcess =
        ( Process * ) Hashtable_get( this->processTable, pid );

    if ( existingProcess ) {
      assert( Vector_indexOf( this->processes, existingProcess,
                              Process_pidCompare ) != -1 );
      process = existingProcess;
      assert( process->pid == pid );
    }
    else {
      process = prototype;
      assert( process->comm == NULL );
      process->pid = pid;
    }

    process->updated = true;

    ProcessList_getCmdLine( ki, command_name, sizeof( command_name ),
                            &cmdlen, 0, 1 );

    user_time = ki->tasks_info.user_time;
    time_value_add( &user_time, &ki->times.user_time );
    system_time = ki->tasks_info.system_time;
    time_value_add( &system_time, &ki->times.system_time );
    total_time = user_time;
    time_value_add( &total_time, &system_time );

    process->st_uid = e->e_pcred.p_ruid;
    process->m_size = ( u_long ) ki->tasks_info.virtual_size / PAGE_SIZE;
    process->m_resident = ( u_long ) ki->tasks_info.resident_size / PAGE_SIZE;
    process->m_share = ( u_long ) ( ki->shared / PAGE_SIZE );
    process->m_trs = 0;         // TODO code
    process->m_lrs = 0;         // TODO data/stack
    process->m_drs = 0;         // TODO library
    process->m_dt = 0;          // TODO dirty

    process->state =
        ProcessList_decodeState( p->p_stat == SZOMB ? SZOMB : ki->state );
    process->ppid = e->e_ppid;
    process->pgrp = e->e_pgid;  // TODO check this
    //process->session       = e->e_sess;
    process->session = 0;       // TODO
    process->tty_nr = e->e_tdev;
    process->tgid = pid;        // TODO check this
    process->tpgid = 0;         // TODO
    process->flags = p->p_flag;
    process->utime = user_time.seconds;
    process->stime = system_time.seconds;
    process->cutime = 0;        // TODO 
    process->cstime = 0;        // TODO
    process->priority = ki->curpri;
    process->nice = p->p_nice;
    process->nlwp = 0;          // TODO
    process->exit_signal = 0;   // TODO
    process->processor = 0;     // TODO
    //process->vpid          = 0;         // TODO
    //process->cpid          = 0;         // TODO
    if ( process->comm )
      free( process->comm );
    process->comm = cmdlen ? String_copy( command_name ) : NULL;

    process->percent_cpu = ki->cpu_usage * 100 / TH_USAGE_SCALE;
    process->percent_mem = ( ( float ) ki->tasks_info.resident_size )
        * 100 / this->totalMem / 1024;

    if ( process->state == 'R' )
      this->runningTasks++;

    if ( !existingProcess ) {
      process = Process_clone( process );
      process->user = UsersTable_getRef(this->usersTable, process->st_uid);
      ProcessList_add( this, process );
    }
  }

  free( kprocbuf );

  return true;
}

void
ProcessList_scan( ProcessList * this ) {
  unsigned long long int usertime, nicetime, systemtime,
      systemalltime, idlealltime, idletime, totaltime;

  mach_msg_type_number_t infoCount;
  vm_statistics_data_t vm_stat;

  infoCount = sizeof( vm_statistics_data_t ) / sizeof( integer_t );

  noerr( host_statistics( mach_host_self(  ), HOST_VM_INFO,
                          ( host_info_t ) & vm_stat, &infoCount ) );

  this->freeMem = this->pageSize * vm_stat.free_count / 1024;
  this->sharedMem = 0;
  this->buffersMem = 0;
  this->cachedMem = 0;

  this->usedMem = this->totalMem - this->freeMem;

  unsigned int cpu_count;
  processor_cpu_load_info_t cpu_load;
  mach_msg_type_number_t cpu_msg_count;

  noerr( host_processor_info( mach_host_self(  ), PROCESSOR_CPU_LOAD_INFO,
                              &cpu_count,
                              ( processor_info_array_t * ) & cpu_load,
                              &cpu_msg_count ) );

#define ZSLOT( n ) \
   do { this->n[0] = 0; } while (0)
#define UPSLOT( n, v ) \
   do { this->n[i] = (v); this->n[0] += this->n[i]; } while (0)

  ZSLOT( userPeriod );
  ZSLOT( nicePeriod );
  ZSLOT( systemPeriod );
  ZSLOT( systemAllPeriod );
  ZSLOT( idleAllPeriod );
  ZSLOT( idlePeriod );
  ZSLOT( ioWaitPeriod );
  ZSLOT( irqPeriod );
  ZSLOT( softIrqPeriod );
  ZSLOT( stealPeriod );
  ZSLOT( totalPeriod );
  ZSLOT( userTime );
  ZSLOT( niceTime );
  ZSLOT( systemTime );
  ZSLOT( systemAllTime );
  ZSLOT( idleAllTime );
  ZSLOT( idleTime );
  ZSLOT( ioWaitTime );
  ZSLOT( irqTime );
  ZSLOT( softIrqTime );
  ZSLOT( stealTime );
  ZSLOT( totalTime );

  for ( int i = 1; i <= cpu_count; i++ ) {
    unsigned long long int ioWait, irq, softIrq, steal;

    usertime = cpu_load[i - 1].cpu_ticks[CPU_STATE_USER];
    nicetime = cpu_load[i - 1].cpu_ticks[CPU_STATE_NICE];
    systemtime = cpu_load[i - 1].cpu_ticks[CPU_STATE_SYSTEM];
    idletime = cpu_load[i - 1].cpu_ticks[CPU_STATE_IDLE];
    ioWait = 0;
    irq = 0;
    softIrq = 0;
    steal = 0;

    idlealltime = idletime + ioWait;
    systemalltime = systemtime + irq + softIrq + steal;
    totaltime = usertime + nicetime + systemalltime + idlealltime;

    UPSLOT( userPeriod, usertime - this->userTime[i] );
    UPSLOT( nicePeriod, nicetime - this->niceTime[i] );
    UPSLOT( systemPeriod, systemtime - this->systemTime[i] );
    UPSLOT( systemAllPeriod, systemalltime - this->systemAllTime[i] );
    UPSLOT( idleAllPeriod, idlealltime - this->idleAllTime[i] );
    UPSLOT( idlePeriod, idletime - this->idleTime[i] );
    UPSLOT( ioWaitPeriod, ioWait - this->ioWaitTime[i] );
    UPSLOT( irqPeriod, irq - this->irqTime[i] );
    UPSLOT( softIrqPeriod, softIrq - this->softIrqTime[i] );
    UPSLOT( stealPeriod, steal - this->stealTime[i] );
    UPSLOT( totalPeriod, totaltime - this->totalTime[i] );
    UPSLOT( userTime, usertime );
    UPSLOT( niceTime, nicetime );
    UPSLOT( systemTime, systemtime );
    UPSLOT( systemAllTime, systemalltime );
    UPSLOT( idleAllTime, idlealltime );
    UPSLOT( idleTime, idletime );
    UPSLOT( ioWaitTime, ioWait );
    UPSLOT( irqTime, irq );
    UPSLOT( softIrqTime, softIrq );
    UPSLOT( stealTime, steal );
    UPSLOT( totalTime, totaltime );
  }

  vm_deallocate( mach_task_self(  ),
                 ( vm_address_t ) cpu_load,
                 ( vm_size_t ) ( cpu_msg_count * sizeof( *cpu_load ) ) );

  float period = ( float ) this->totalPeriod[0] / cpu_count;

  // mark all process as "dirty"
  for ( int i = 0; i < Vector_size( this->processes ); i++ ) {
    Process *p = ( Process * ) Vector_get( this->processes, i );
    p->updated = false;
  }

  this->totalTasks = 0;
  this->runningTasks = 0;

  ProcessList_getProcesses( this, period );
  ProcessList_getSwap( this );

  for ( int i = Vector_size( this->processes ) - 1; i >= 0; i-- ) {
    Process *p = ( Process * ) Vector_get( this->processes, i );
    if ( p->updated == false )
      ProcessList_remove( this, p );
    else
      p->updated = false;
  }

}

ProcessField
ProcessList_keyAt( ProcessList * this, int at ) {
  int x = 0;
  ProcessField *fields = this->fields;
  ProcessField field;
  for ( int i = 0; ( field = fields[i] ); i++ ) {
    int len = strlen( Process_fieldTitles[field] );
    if ( at >= x && at <= x + len ) {
      return field;
    }
    x += len;
  }
  return COMM;
}
