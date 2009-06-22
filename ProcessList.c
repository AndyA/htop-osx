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
#include "libtop.h"

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
ProcessList_getProcesses( ProcessList * this, float period ) {
  const libtop_psamp_t *proc;

  while ( ( proc = libtop_piterate(  ) ) ) {
    int pid = proc->pid;
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
      process = this->prototype;
      assert( process->comm == NULL );
      process->pid = pid;
    }

    process->updated = true;
    process->st_uid = proc->uid;
    process->m_size = proc->vsize / 1024;
    process->m_resident = proc->rsize / 1024;
    process->m_share = proc->rshrd / 1024;
    process->m_trs = 0;         // TODO code
    process->m_lrs = 0;         // TODO data/stack
    process->m_drs = 0;         // TODO library
    process->m_dt = 0;          // TODO dirty
    process->state = ProcessList_decodeState( proc->state );
    process->ppid = proc->ppid;
    process->pgrp = proc->pgrp;
    process->session = 0;       // TODO
    process->tty_nr = 0;        // TODO
    process->tgid = pid;        // TODO check this
    process->tpgid = 0;         // TODO
    process->tgid = pid;        // TODO check this
    process->tpgid = 0;         // TODO
    process->flags = 0;
    // TODO how do we get the broken down time?
    process->utime = proc->total_time.tv_sec;
    process->stime = 0;
    process->cutime = 0;        // TODO 
    process->cstime = 0;        // TODO
    process->priority = 0;      // TODO
    process->nice = 0;          // TODO
    process->nlwp = 0;          // TODO
    process->exit_signal = 0;   // TODO
    process->processor = 0;     // TODO
    //process->vpid          = 0;         // TODO
    //process->cpid          = 0;         // TODO

    process->comm = proc->command;

    process->percent_cpu = 0;   //ki->cpu_usage * 100 / TH_USAGE_SCALE;
    process->percent_mem = process->m_resident * 100 / this->totalMem;

    if ( process->state == 'R' )
      this->runningTasks++;

    if ( !existingProcess ) {
      process = Process_clone( process );
      ProcessList_add( this, process );
    }

  }

  return true;
}

void
ProcessList_scan( ProcessList * this ) {
  const libtop_tsamp_t *samp;
  unsigned long long int usertime, nicetime, systemtime,
      systemalltime, idlealltime, idletime, totaltime;

  mach_msg_type_number_t infoCount;
  vm_statistics_data_t vm_stat;

  // TODO set the options as parsimoniously as possible - they
  // use a lot of CPU

  libtop_sample( true, true );
  samp = libtop_tsamp(  );

  infoCount = sizeof( vm_statistics_data_t ) / sizeof( integer_t );

  noerr( host_statistics( mach_host_self(  ), HOST_VM_INFO,
                          ( host_info_t ) & vm_stat, &infoCount ) );

  this->freeMem = samp->pagesize * samp->vm_stat.free_count / 1024;
  this->sharedMem = samp->rshrd / 1024;
  this->buffersMem = 0;
  this->cachedMem = 0;
  this->totalSwap = 0;
  this->freeSwap = 0;

  this->usedMem = this->totalMem - this->freeMem;
  this->usedSwap = this->totalSwap - this->freeSwap;

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
