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

/*{
#ifndef PROCDIR
#define PROCDIR "../proc"
#endif

#ifndef PROCSTATFILE
#define PROCSTATFILE PROCDIR "/stat"
#endif

#ifndef PROCMEMINFOFILE
#define PROCMEMINFOFILE PROCDIR "/meminfo"
#endif

#ifndef MAX_NAME
#define MAX_NAME 128
#endif

#ifndef MAX_READ
#define MAX_READ 2048
#endif

#ifndef PER_PROCESSOR_FIELDS
#define PER_PROCESSOR_FIELDS 22
#endif

#define KI_PROC(ki) (&(ki)->ki_p->kp_proc)
#define KI_EPROC(ki) (&(ki)->ki_p->kp_eproc)
#define STATE_MAX       7

}*/

/*{

#ifdef DEBUG_PROC
typedef int(*vxscanf)(void*, const char*, va_list);
#endif

typedef struct ProcessList_ {
   Vector* processes;
   Vector* processes2;
   Hashtable* processTable;
   Process* prototype;
   UsersTable* usersTable;

   int processorCount;
   int totalTasks;
   int runningTasks;
   vm_size_t pageSize;

   // Must match number of PER_PROCESSOR_FIELDS constant
   unsigned long long int* totalTime;
   unsigned long long int* userTime;
   unsigned long long int* systemTime;
   unsigned long long int* systemAllTime;
   unsigned long long int* idleAllTime;
   unsigned long long int* idleTime;
   unsigned long long int* niceTime;
   unsigned long long int* ioWaitTime;
   unsigned long long int* irqTime;
   unsigned long long int* softIrqTime;
   unsigned long long int* stealTime;
   unsigned long long int* totalPeriod;
   unsigned long long int* userPeriod;
   unsigned long long int* systemPeriod;
   unsigned long long int* systemAllPeriod;
   unsigned long long int* idleAllPeriod;
   unsigned long long int* idlePeriod;
   unsigned long long int* nicePeriod;
   unsigned long long int* ioWaitPeriod;
   unsigned long long int* irqPeriod;
   unsigned long long int* softIrqPeriod;
   unsigned long long int* stealPeriod;

   unsigned long long int totalMem;
   unsigned long long int usedMem;
   unsigned long long int freeMem;
   unsigned long long int sharedMem;
   unsigned long long int buffersMem;
   unsigned long long int cachedMem;
   unsigned long long int totalSwap;
   unsigned long long int usedSwap;
   unsigned long long int freeSwap;

   ProcessField* fields;
   ProcessField sortKey;
   int direction;
   bool hideThreads;
   bool shadowOtherUsers;
   bool hideKernelThreads;
   bool hideUserlandThreads;
   bool treeView;
   bool highlightBaseName;
   bool highlightMegabytes;
   bool highlightThreads;
   bool detailedCPUTime;
   #ifdef DEBUG_PROC
   FILE* traceFile;
   #endif

} ProcessList;

}*/

/*{

typedef struct thread_values {
	struct thread_basic_info tb;
	union {
		struct policy_timeshare_info tshare;
		struct policy_rr_info rr;
		struct policy_fifo_info fifo;
	} schedinfo;
} thread_values_t;

}*/

/*{

struct usave {
	struct	timeval u_start;
	struct	rusage u_ru;
	struct	rusage u_cru;
	char	u_acflag;
	char	u_valid;
};

typedef struct kinfo {
	struct kinfo_proc *ki_p;
	struct usave ki_u;
	char *ki_args;
	char *ki_env;
	task_port_t task;
	int state;
	int cpu_usage;
	int curpri;
	int basepri;
	int swapped;
	struct task_basic_info tasks_info;
	struct task_thread_times_info times;
	union {
		struct policy_timeshare_info tshare;
		struct policy_rr_info rr;
		struct policy_fifo_info fifo;
	} schedinfo;
	int	invalid_tinfo;
	mach_msg_type_number_t	thread_count;
	thread_port_array_t thread_list;
	thread_values_t *thval;
	int	invalid_thinfo;
} KINFO;

}*/

static ProcessField defaultHeaders[] = { PID, USER, PRIORITY, NICE, M_SIZE, M_RESIDENT, M_SHARE, STATE, PERCENT_CPU, PERCENT_MEM, TIME, COMM, 0 };

#ifdef DEBUG_PROC

#define ProcessList_read(this, buffer, format, ...) ProcessList_xread(this, (vxscanf) vsscanf, buffer, format, ## __VA_ARGS__ )
#define ProcessList_fread(this, file, format, ...)  ProcessList_xread(this, (vxscanf) vfscanf, file, format, ## __VA_ARGS__ )

static FILE* ProcessList_fopen(ProcessList* this, const char* path, const char* mode) {
   fprintf(this->traceFile, "[%s]\n", path);
   return fopen(path, mode);
}

static inline int ProcessList_xread(ProcessList* this, vxscanf fn, void* buffer, char* format, ...) {
   va_list ap;
   va_start(ap, format);
   int num = fn(buffer, format, ap);
   va_end(format);
   va_start(ap, format);
   while (*format) {
      char ch = *format;
      char* c; int* d;
      long int* ld; unsigned long int* lu;
      long long int* lld; unsigned long long int* llu;
      char** s;
      if (ch != '%') {
         fprintf(this->traceFile, "%c", ch);
         format++;
         continue;
      }
      format++;
      switch(*format) {
      case 'c': c = va_arg(ap, char*);  fprintf(this->traceFile, "%c", *c); break;
      case 'd': d = va_arg(ap, int*);   fprintf(this->traceFile, "%d", *d); break;
      case 's': s = va_arg(ap, char**); fprintf(this->traceFile, "%s", *s); break;
      case 'l':
         format++;
         switch (*format) {
         case 'd': ld = va_arg(ap, long int*); fprintf(this->traceFile, "%ld", *ld); break;
         case 'u': lu = va_arg(ap, unsigned long int*); fprintf(this->traceFile, "%lu", *lu); break;
         case 'l':
            format++;
            switch (*format) {
            case 'd': lld = va_arg(ap, long long int*); fprintf(this->traceFile, "%lld", *lld); break;
            case 'u': llu = va_arg(ap, unsigned long long int*); fprintf(this->traceFile, "%llu", *llu); break;
            }
         }
      }
      format++;
   }
   fprintf(this->traceFile, "\n");
   va_end(format);
   return num;
}

#else

#ifndef ProcessList_read
#define ProcessList_fopen(this, path, mode) fopen(path, mode)
#define ProcessList_read(this, buffer, format, ...) sscanf(buffer, format, ## __VA_ARGS__ )
#define ProcessList_fread(this, file, format, ...) fscanf(file, format, ## __VA_ARGS__ )
#endif

#endif

static inline void ProcessList_allocatePerProcessorBuffers(ProcessList* this, int procs) {
   unsigned long long int** bufferPtr = &(this->totalTime);
   unsigned long long int* buffer = calloc(procs * PER_PROCESSOR_FIELDS, sizeof(unsigned long long int));
   for (int i = 0; i < PER_PROCESSOR_FIELDS; i++) {
      *bufferPtr = buffer;
      bufferPtr++;
      buffer += procs;
   }
}

ProcessList* ProcessList_new(UsersTable* usersTable) {
   ProcessList* this;
   host_basic_info_data_t hostInfo;
   mach_msg_type_number_t infoCount;

   this = malloc(sizeof(ProcessList));
   this->processes = Vector_new(PROCESS_CLASS, true, DEFAULT_SIZE, Process_compare);
   this->processTable = Hashtable_new(70, false);
   assert(Hashtable_count(this->processTable) == Vector_count(this->processes));
   this->prototype = Process_new(this);
   this->usersTable = usersTable;
   
   /* tree-view auxiliary buffers */
   this->processes2 = Vector_new(PROCESS_CLASS, true, DEFAULT_SIZE, Process_compare);
   
   #ifdef DEBUG_PROC
   this->traceFile = fopen("/tmp/htop-proc-trace", "w");
   #endif

   infoCount = HOST_BASIC_INFO_COUNT;
   noerr(host_info(mach_host_self(), HOST_BASIC_INFO, 
               (host_info_t) &hostInfo, &infoCount));
   this->processorCount = hostInfo.avail_cpus;
   this->totalMem       = hostInfo.max_mem / 1024;

   host_page_size(mach_host_self(), &this->pageSize);
   
   /* TODO not sure we need the +1 here */
   ProcessList_allocatePerProcessorBuffers(this, hostInfo.avail_cpus + 1);

   for (int i = 0; i < hostInfo.avail_cpus + 1; i++) {
      this->totalTime[i] = 1;
      this->totalPeriod[i] = 1;
   }

   this->fields = calloc(sizeof(ProcessField), LAST_PROCESSFIELD+1);
   // TODO: turn 'fields' into a Vector,
   // (and ProcessFields into proper objects).
   for (int i = 0; defaultHeaders[i]; i++) {
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

void ProcessList_delete(ProcessList* this) {
   Hashtable_delete(this->processTable);
   Vector_delete(this->processes);
   Vector_delete(this->processes2);
   Process_delete((Object*)this->prototype);

   // Free first entry only;
   // other fields are offsets of the same buffer
   free(this->totalTime);

   #ifdef DEBUG_PROC
   fclose(this->traceFile);
   #endif

   free(this->fields);
/*   free(this);*/
}

void ProcessList_invertSortOrder(ProcessList* this) {
   if (this->direction == 1)
      this->direction = -1;
   else
      this->direction = 1;
}

RichString ProcessList_printHeader(ProcessList* this) {
   RichString out;
   RichString_initVal(out);
   ProcessField* fields = this->fields;
   for (int i = 0; fields[i]; i++) {
      char* field = Process_fieldTitles[fields[i]];
      if (this->sortKey == fields[i])
         RichString_append(&out, CRT_colors[PANEL_HIGHLIGHT_FOCUS], field);
      else
         RichString_append(&out, CRT_colors[PANEL_HEADER_FOCUS], field);
   }
   return out;
}

static void ProcessList_add(ProcessList* this, Process* p) {
   assert(Vector_indexOf(this->processes, p, Process_pidCompare) == -1);
   assert(Hashtable_get(this->processTable, p->pid) == NULL);
   Vector_add(this->processes, p);
   Hashtable_put(this->processTable, p->pid, p);
   assert(Vector_indexOf(this->processes, p, Process_pidCompare) != -1);
   assert(Hashtable_get(this->processTable, p->pid) != NULL);
   assert(Hashtable_count(this->processTable) == Vector_count(this->processes));
}

static void ProcessList_remove(ProcessList* this, Process* p) {
   assert(Vector_indexOf(this->processes, p, Process_pidCompare) != -1);
   assert(Hashtable_get(this->processTable, p->pid) != NULL);
   Process* pp = Hashtable_remove(this->processTable, p->pid);
   assert(pp == p); (void)pp;
   unsigned int pid = p->pid;
   int index = Vector_indexOf(this->processes, p, Process_pidCompare);
   assert(index != -1);
   Vector_remove(this->processes, index);
   assert(Hashtable_get(this->processTable, pid) == NULL); (void)pid;
   assert(Hashtable_count(this->processTable) == Vector_count(this->processes));
}

Process* ProcessList_get(ProcessList* this, int index) {
   return (Process*) (Vector_get(this->processes, index));
}

int ProcessList_size(ProcessList* this) {
   return (Vector_size(this->processes));
}

static void ProcessList_buildTree(ProcessList* this, int pid, int level, int indent, int direction) {
   Vector* children = Vector_new(PROCESS_CLASS, false, DEFAULT_SIZE, Process_compare);

   for (int i = Vector_size(this->processes) - 1; i >= 0; i--) {
      Process* process = (Process*) (Vector_get(this->processes, i));
      if (process->tgid == pid || (process->tgid == process->pid && process->ppid == pid)) {
         Process* process = (Process*) (Vector_take(this->processes, i));
         Vector_add(children, process);
      }
   }
   int size = Vector_size(children);
   for (int i = 0; i < size; i++) {
      Process* process = (Process*) (Vector_get(children, i));
      int s = this->processes2->items;
      if (direction == 1)
         Vector_add(this->processes2, process);
      else
         Vector_insert(this->processes2, 0, process);
      assert(this->processes2->items == s+1); (void)s;
      int nextIndent = indent;
      if (i < size - 1)
         nextIndent = indent | (1 << level);
      ProcessList_buildTree(this, process->pid, level+1, nextIndent, direction);
      process->indent = indent | (1 << level);
   }
   Vector_delete(children);
}

void ProcessList_sort(ProcessList* this) {
   if (!this->treeView) {
      Vector_sort(this->processes);
   } else {
      // Save settings
      int direction = this->direction;
      int sortKey = this->sortKey;
      // Sort by PID
      this->sortKey = PID;
      this->direction = 1;
      Vector_sort(this->processes);
      // Restore settings
      this->sortKey = sortKey;
      this->direction = direction;
      // Take PID 1 as root and add to the new listing
      int vsize = Vector_size(this->processes);
      Process* init = (Process*) (Vector_take(this->processes, 0));
      // This assertion crashes on hardened kernels.
      // I wonder how well tree view works on those systems.
      // assert(init->pid == 1);
      init->indent = 0;
      Vector_add(this->processes2, init);
      // Recursively empty list
      ProcessList_buildTree(this, init->pid, 0, 0, direction);
      // Add leftovers
      while (Vector_size(this->processes)) {
         Process* p = (Process*) (Vector_take(this->processes, 0));
         p->indent = 0;
         Vector_add(this->processes2, p);
         ProcessList_buildTree(this, p->pid, 0, 0, direction);
      }
      assert(Vector_size(this->processes2) == vsize); (void)vsize;
      assert(Vector_size(this->processes) == 0);
      // Swap listings around
      Vector* t = this->processes;
      this->processes = this->processes2;
      this->processes2 = t;
   }
}

static int ProcessList_readStatFile(ProcessList* this, Process *proc, FILE *f, char *command) {
   static char buf[MAX_READ];
   unsigned long int zero;

   int size = fread(buf, 1, MAX_READ, f);
   if(!size) return 0;

   assert(proc->pid == atoi(buf));
   char *location = strchr(buf, ' ');
   if(!location) return 0;

   location += 2;
   char *end = strrchr(location, ')');
   if(!end) return 0;
   
   int commsize = end - location;
   memcpy(command, location, commsize);
   command[commsize] = '\0';
   location = end + 2;
   
   #ifdef DEBUG_PROC
   int num = ProcessList_read(this, location, 
      "%c %u %u %u %u %d %lu %lu %lu %lu "
      "%lu %lu %lu %ld %ld %ld %ld %ld %ld "
      "%lu %lu %ld %lu %lu %lu %lu %lu "
      "%lu %lu %lu %lu %lu %lu %lu %lu "
      "%d %d",
      &proc->state, &proc->ppid, &proc->pgrp, &proc->session, &proc->tty_nr, 
      &proc->tpgid, &proc->flags,
      &proc->minflt, &proc->cminflt, &proc->majflt, &proc->cmajflt,
      &proc->utime, &proc->stime, &proc->cutime, &proc->cstime, 
      &proc->priority, &proc->nice, &proc->nlwp, &proc->itrealvalue,
      &proc->starttime, &proc->vsize, &proc->rss, &proc->rlim, 
      &proc->startcode, &proc->endcode, &proc->startstack, &proc->kstkesp, 
      &proc->kstkeip, &proc->signal, &proc->blocked, &proc->sigignore, 
      &proc->sigcatch, &proc->wchan, &proc->nswap, &proc->cnswap, 
      &proc->exit_signal, &proc->processor);
   #else
   long int uzero;
   int num = ProcessList_read(this, location, 
      "%c %u %u %u %u %d %lu %lu %lu %lu "
      "%lu %lu %lu %ld %ld %ld %ld %ld %ld "
      "%lu %lu %ld %lu %lu %lu %lu %lu "
      "%lu %lu %lu %lu %lu %lu %lu %lu "
      "%d %d",
      &proc->state, &proc->ppid, &proc->pgrp, &proc->session, &proc->tty_nr, 
      &proc->tpgid, &proc->flags,
      &zero, &zero, &zero, &zero,
      &proc->utime, &proc->stime, &proc->cutime, &proc->cstime, 
      &proc->priority, &proc->nice, &proc->nlwp, &uzero,
      &zero, &zero, &uzero, &zero, 
      &zero, &zero, &zero, &zero, 
      &zero, &zero, &zero, &zero, 
      &zero, &zero, &zero, &zero, 
      &proc->exit_signal, &proc->processor);
   #endif
   
   // This assert is always valid on 2.4, but reportedly not always valid on 2.6.
   // TODO: Check if the semantics of this field has changed.
   // assert(zero == 0);
   
   if(num != 37) return 0;
   return 1;
}

static bool ProcessList_readStatusFile(ProcessList* this, Process* proc, char* dirname, char* name) {
   char statusfilename[MAX_NAME+1];
   statusfilename[MAX_NAME] = '\0';

   snprintf(statusfilename, MAX_NAME, "%s/%s", dirname, name);
   struct stat sstat;
   int statok = stat(statusfilename, &sstat);
   if (statok == -1)
      return false;
   proc->st_uid = sstat.st_uid;
   return true;
}

#ifdef HAVE_TASKSTATS

static void ProcessList_readIoFile(ProcessList* this, Process* proc, char* dirname, char* name) {
   char iofilename[MAX_NAME+1];
   iofilename[MAX_NAME] = '\0';

   snprintf(iofilename, MAX_NAME, "%s/%s/io", dirname, name);
   FILE* io = ProcessList_fopen(this, iofilename, "r");
   if (io) {
      char buffer[256];
      buffer[255] = '\0';
      struct timeval tv;
      gettimeofday(&tv,NULL);
      unsigned long long now = tv.tv_sec*1000+tv.tv_usec/1000;
      unsigned long long last_read = proc->io_read_bytes;
      unsigned long long last_write = proc->io_write_bytes;
      while (!feof(io)) {
         char* ok = fgets(buffer, 255, io);
         if (!ok)
            break;
         if (ProcessList_read(this, buffer, "rchar: %llu", &proc->io_rchar)) continue;
         if (ProcessList_read(this, buffer, "wchar: %llu", &proc->io_wchar)) continue;
         if (ProcessList_read(this, buffer, "syscr: %llu", &proc->io_syscr)) continue;
         if (ProcessList_read(this, buffer, "syscw: %llu", &proc->io_syscw)) continue;
         if (ProcessList_read(this, buffer, "read_bytes: %llu", &proc->io_read_bytes)) {
            proc->io_rate_read_bps = 
               ((double)(proc->io_read_bytes - last_read))/(((double)(now - proc->io_rate_read_time))/1000);
            proc->io_rate_read_time = now;
            continue;
         }
         if (ProcessList_read(this, buffer, "write_bytes: %llu", &proc->io_write_bytes)) {
            proc->io_rate_write_bps = 
               ((double)(proc->io_write_bytes - last_write))/(((double)(now - proc->io_rate_write_time))/1000);
            proc->io_rate_write_time = now;
            continue;
         }
         ProcessList_read(this, buffer, "cancelled_write_bytes: %llu", &proc->io_cancelled_write_bytes);
      }
      fclose(io);
   }
}

#endif

/* huh? */

static int ProcessList_MachStateOrder(int s, long sleep_time) {
	switch (s) {
	case TH_STATE_RUNNING:		      return 1;
	case TH_STATE_UNINTERRUPTIBLE:   return 2;
	case TH_STATE_WAITING:		      return (sleep_time > 20) ? 4 : 3;
	case TH_STATE_STOPPED:		      return 5;
	case TH_STATE_HALTED:		      return 6;  
	default:					            return 7; 
	}
}

static int thread_schedinfo(KINFO *ki, thread_port_t thread, policy_t pol, void * buf) {
	unsigned int		count;
	int ret = KERN_FAILURE;

	switch (pol) {

	case POLICY_TIMESHARE:
		count = POLICY_TIMESHARE_INFO_COUNT;
		ret = thread_info(thread, THREAD_SCHED_TIMESHARE_INFO,
					(thread_info_t)buf, &count);
		if((ret == KERN_SUCCESS) && (ki->curpri < (((struct policy_timeshare_info *)buf)->cur_priority)))
			ki->curpri  = ((struct policy_timeshare_info *)buf)->cur_priority;
		break;

	case POLICY_FIFO:
		count = POLICY_FIFO_INFO_COUNT;
		ret = thread_info(thread, THREAD_SCHED_FIFO_INFO,
					buf, &count);
		if((ret == KERN_SUCCESS) && (ki->curpri < (((struct policy_fifo_info *)buf)->base_priority)))
			ki->curpri  = ((struct policy_fifo_info *)buf)->base_priority;
		break;

	case POLICY_RR:
		count = POLICY_RR_INFO_COUNT;
		ret = thread_info(thread, THREAD_SCHED_RR_INFO,
					buf, &count);
		if((ret == KERN_SUCCESS) && (ki->curpri < (((struct policy_rr_info *)buf)->base_priority)))
			ki->curpri  = ((struct policy_rr_info *)buf)->base_priority;
		break;
	}
	return ret;
}

static int get_task_info(KINFO *ki) {
	kern_return_t   	error;
	unsigned int		info_count = TASK_BASIC_INFO_COUNT;
	unsigned int 		thread_info_count = THREAD_BASIC_INFO_COUNT;
	pid_t				pid;
	int j, err = 0;

	pid = KI_PROC(ki)->p_pid;
	if (task_for_pid(mach_task_self(), pid, &ki->task) != KERN_SUCCESS) {
		return 1;
	}
	info_count = TASK_BASIC_INFO_COUNT;
	error = task_info(ki->task, TASK_BASIC_INFO, 
         (task_info_t) &ki->tasks_info, &info_count);

	if (error != KERN_SUCCESS) {
		ki->invalid_tinfo=1;
		return 1;
	}

	{
		vm_region_basic_info_data_64_t	b_info;
		vm_address_t					address = GLOBAL_SHARED_TEXT_SEGMENT;
		vm_size_t					size;
		mach_port_t					object_name;

		/*
		 * try to determine if this task has the split libraries
		 * mapped in... if so, adjust its virtual size down by
		 * the 2 segments that are used for split libraries
		 */
		info_count = VM_REGION_BASIC_INFO_COUNT_64;
		error = vm_region_64(ki->task, &address, &size, VM_REGION_BASIC_INFO,
					(vm_region_info_t)&b_info, &info_count, &object_name);
		if (error == KERN_SUCCESS) {
			if (b_info.reserved && size == (SHARED_TEXT_REGION_SIZE) &&
				ki->tasks_info.virtual_size > 
            (SHARED_TEXT_REGION_SIZE + SHARED_DATA_REGION_SIZE))
					ki->tasks_info.virtual_size -= 
                  (SHARED_TEXT_REGION_SIZE + SHARED_DATA_REGION_SIZE);
		}
	}
	info_count = TASK_THREAD_TIMES_INFO_COUNT;
	error = task_info(ki->task, TASK_THREAD_TIMES_INFO,
         (task_info_t) &ki->times, &info_count);
	if (error != KERN_SUCCESS) {
		ki->invalid_tinfo=1;
		return 1;
	}

	switch(ki->tasks_info.policy) {

		case POLICY_TIMESHARE :
			info_count = POLICY_TIMESHARE_INFO_COUNT;
			error = task_info(ki->task, TASK_SCHED_TIMESHARE_INFO, (task_info_t) &ki->schedinfo.tshare, &info_count);
			if (error != KERN_SUCCESS) {
				ki->invalid_tinfo=1;
				return 1;
			}

			ki->curpri = ki->schedinfo.tshare.cur_priority;
			ki->basepri = ki->schedinfo.tshare.base_priority;
			break;

		case POLICY_RR :
	 		info_count = POLICY_RR_INFO_COUNT;
			error = task_info(ki->task, TASK_SCHED_RR_INFO, (task_info_t) &ki->schedinfo.rr, &info_count);
			if (error != KERN_SUCCESS) {
				ki->invalid_tinfo=1;
				return 1;
			}

			ki->curpri = ki->schedinfo.rr.base_priority;
			ki->basepri = ki->schedinfo.rr.base_priority;
			break;

		case POLICY_FIFO :
			info_count = POLICY_FIFO_INFO_COUNT;
			error = task_info(ki->task, TASK_SCHED_FIFO_INFO, (task_info_t) &ki->schedinfo.fifo, &info_count);
			if (error != KERN_SUCCESS) {
				ki->invalid_tinfo=1;
				return 1;
			}

			ki->curpri = ki->schedinfo.fifo.base_priority;
			ki->basepri = ki->schedinfo.fifo.base_priority;
			break;
	}

	ki->invalid_tinfo=0;

	ki->cpu_usage=0;
	error = task_threads(ki->task, &ki->thread_list, &ki->thread_count);
	if (error != KERN_SUCCESS) {
		mach_port_deallocate(mach_task_self(),ki->task);
		return 1;
	}
	err=0;
	ki->state = STATE_MAX;
	//ki->curpri = 255;
	//ki->basepri = 255;
	ki->swapped = 1;
	ki->thval = malloc(ki->thread_count * sizeof(struct thread_values));
	if (ki->thval != NULL) {
		for (j = 0; j < ki->thread_count; j++) {
			int tstate;
			thread_info_count = THREAD_BASIC_INFO_COUNT;
			error = thread_info(ki->thread_list[j], THREAD_BASIC_INFO,
				(thread_info_t)&ki->thval[j].tb,
				&thread_info_count);
			if (error != KERN_SUCCESS) {
				err=1;
			}
			error = thread_schedinfo(ki, ki->thread_list[j],
				ki->thval[j].tb.policy, &ki->thval[j].schedinfo);
			if (error != KERN_SUCCESS) {
				err=1;
			}
			ki->cpu_usage += ki->thval[j].tb.cpu_usage;
			tstate = ProcessList_MachStateOrder(ki->thval[j].tb.run_state,
					ki->thval[j].tb.sleep_time);
			if (tstate < ki->state)
				ki->state = tstate;
			if ((ki->thval[j].tb.flags & TH_FLAGS_SWAPPED ) == 0)
				ki->swapped = 0;
			mach_port_deallocate(mach_task_self(),
				ki->thread_list[j]);
		}
		free (ki->thval);
		ki->thval = NULL;
	}
	ki->invalid_thinfo = err;
	/* Deallocate the list of threads. */
	error = vm_deallocate(mach_task_self(), 
		(vm_address_t)(ki->thread_list),
		 sizeof(thread_port_array_t) * ki->thread_count);
	if (error != KERN_SUCCESS) {
	}

	mach_port_deallocate(mach_task_self(),ki->task);
	return 0;
}

static void getproclline(KINFO *k, char **command_name, int *cmdlen, int eflg, int show_args) {
	int		mib[3], argmax, nargs, c = 0;
	size_t		size;
	char		*procargs, *sp, *np, *cp;
/*  Made into a command argument. -- TRW
 *	extern int	eflg;
 */

	/* Get the maximum process arguments size. */
	mib[0] = CTL_KERN;
	mib[1] = KERN_ARGMAX;

	size = sizeof(argmax);
	if (sysctl(mib, 2, &argmax, &size, NULL, 0) == -1) {
		goto ERROR_A;
	}

	/* Allocate space for the arguments. */
	procargs = (char *)malloc(argmax);
	if (procargs == NULL) {
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
	mib[2] = KI_PROC(k)->p_pid;

	size = (size_t)argmax;
	if (sysctl(mib, 3, procargs, &size, NULL, 0) == -1) {
		goto ERROR_B;
	}

	memcpy(&nargs, procargs, sizeof(nargs));
	cp = procargs + sizeof(nargs);

	/* Skip the saved exec_path. */
	for (; cp < &procargs[size]; cp++) {
		if (*cp == '\0') {
			/* End of exec_path reached. */
			break;
		}
	}
	if (cp == &procargs[size]) {
		goto ERROR_B;
	}

	/* Skip trailing '\0' characters. */
	for (; cp < &procargs[size]; cp++) {
		if (*cp != '\0') {
			/* Beginning of first argument reached. */
			break;
		}
	}
	if (cp == &procargs[size]) {
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
	for (np = NULL; c < nargs && cp < &procargs[size]; cp++) {
		if (*cp == '\0') {
			c++;
			if (np != NULL) {
				/* Convert previous '\0'. */
				*np = ' ';
			}
			/* Note location of current '\0'. */
			np = cp;

			if (!show_args) {
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
	if ( (eflg != 0) && ( (getuid() == 0) || (KI_EPROC(k)->e_pcred.p_ruid == getuid()) ) ) {
		for (; cp < &procargs[size]; cp++) {
			if (*cp == '\0') {
				if (np != NULL) {
					if (&np[1] == cp) {
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
	if (np == NULL || np == sp) {
		/* Empty or unterminated string. */
		goto ERROR_B;
	}

	/* Make a copy of the string. */
	*cmdlen = asprintf(command_name, "%s", sp);

	/* Clean up. */
	free(procargs);
	return;

	ERROR_B:
	free(procargs);
	ERROR_A:
	*cmdlen = asprintf(command_name, "(%s)", KI_PROC(k)->p_comm);
}

static bool ProcessList_getProcesses(ProcessList *this, float period) {
	struct kinfo_proc *kp;
	struct kinfo_proc *kprocbuf = NULL;
	size_t bufSize = 0;
	int nentries;
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };

	if (sysctl(mib, 4, NULL, &bufSize, NULL, 0) < 0)
		die("Failure calling sysctl");

	if ((kprocbuf = kp = (struct kinfo_proc *) malloc(bufSize)) == NULL)
		die("Memory allocation failure");

	if (sysctl(mib, 4, kp, &bufSize, NULL, 0) < 0)
		die("Failure calling sysctl");

	this->totalTasks = bufSize/ sizeof(struct kinfo_proc);

   for ( int i = 0; i < this->totalTasks; i++ ) {
		struct extern_proc *p;
		struct eproc *e;
		KINFO kinfo;
		memset(&kinfo, 0, sizeof(kinfo));
		KINFO *ki = &kinfo;
		time_value_t total_time, system_time, user_time;
   }

   return true;
}

static bool ProcessList_processEntries(ProcessList* this, char* dirname, Process* parent, float period) {
   DIR* dir;
   struct dirent* entry;
   Process* prototype = this->prototype;

   dir = opendir(dirname);
   if (!dir) return false;
   int processors = this->processorCount;
   bool showUserlandThreads = !this->hideUserlandThreads;
   while ((entry = readdir(dir)) != NULL) {
      char* name = entry->d_name;
      int pid;
      // filename is a number: process directory
      pid = atoi(name);

      // The RedHat kernel hides threads with a dot.
      // I believe this is non-standard.
      bool isThread = false;
      if ((!this->hideThreads) && pid == 0 && name[0] == '.') {
         char* tname = name + 1;
         pid = atoi(tname);
         if (pid > 0)
            isThread = true;
      }

      if (pid > 0) {

         FILE* status;
         char statusfilename[MAX_NAME+1];
         char command[PROCESS_COMM_LEN + 1];

         Process* process = NULL;
         Process* existingProcess = (Process*) Hashtable_get(this->processTable, pid);

         if (existingProcess) {
            assert(Vector_indexOf(this->processes, existingProcess, Process_pidCompare) != -1);
            process = existingProcess;
            assert(process->pid == pid);
         } else {
            if (parent && parent->pid == pid) {
               process = parent;
            } else {
               process = prototype;
               assert(process->comm == NULL);
               process->pid = pid;
            }
         }
         process->tgid = parent ? parent->pid : pid;

         if (showUserlandThreads && (!parent || pid != parent->pid)) {
            char subdirname[MAX_NAME+1];
            snprintf(subdirname, MAX_NAME, "%s/%s/task", dirname, name);
   
            if (ProcessList_processEntries(this, subdirname, process, period))
               continue;
         }

         #ifdef HAVE_TASKSTATS        
         ProcessList_readIoFile(this, process, dirname, name);
         #endif

         process->updated = true;

         if (!existingProcess)
            if (! ProcessList_readStatusFile(this, process, dirname, name))
               goto errorReadingProcess;

         snprintf(statusfilename, MAX_NAME, "%s/%s/statm", dirname, name);
         status = ProcessList_fopen(this, statusfilename, "r");

         if(!status) {
            goto errorReadingProcess;
         }
         int num = ProcessList_fread(this, status, "%d %d %d %d %d %d %d",
             &process->m_size, &process->m_resident, &process->m_share, 
             &process->m_trs, &process->m_lrs, &process->m_drs, 
             &process->m_dt);

         fclose(status);
         if(num != 7)
            goto errorReadingProcess;

         if (this->hideKernelThreads && process->m_size == 0)
            goto errorReadingProcess;

         int lasttimes = (process->utime + process->stime);

         snprintf(statusfilename, MAX_NAME, "%s/%s/stat", dirname, name);
         
         status = ProcessList_fopen(this, statusfilename, "r");
         if (status == NULL)
            goto errorReadingProcess;

         int success = ProcessList_readStatFile(this, process, status, command);
         fclose(status);
         if(!success) {
            goto errorReadingProcess;
         }

         if(!existingProcess) {
            process->user = UsersTable_getRef(this->usersTable, process->st_uid);

            #ifdef HAVE_OPENVZ
            if (access("/proc/vz", R_OK) != 0) {
               process->vpid = process->pid;
               process->ctid = 0;
            } else {
               snprintf(statusfilename, MAX_NAME, "%s/%s/stat", dirname, name);
               status = ProcessList_fopen(this, statusfilename, "r");
               if (status == NULL) 
                  goto errorReadingProcess;
               num = ProcessList_fread(this, status, 
                  "%*u %*s %*c %*u %*u %*u %*u %*u %*u %*u "
                  "%*u %*u %*u %*u %*u %*u %*u %*u "
                  "%*u %*u %*u %*u %*u %*u %*u %*u "
                  "%*u %*u %*u %*u %*u %*u %*u %*u "
                  "%*u %*u %*u %*u %*u %*u %*u %*u "
                  "%*u %*u %*u %*u %*u %*u %*u "
                  "%*u %*u %u %u",
                  &process->vpid, &process->ctid);
               fclose(status);
            }
            #endif

            #ifdef HAVE_VSERVER
            snprintf(statusfilename, MAX_NAME, "%s/%s/status", dirname, name);
            status = ProcessList_fopen(this, statusfilename, "r");
            if (status == NULL) 
               goto errorReadingProcess;
            else {
               char buffer[256];
               process->vxid = 0;
               while (!feof(status)) {
                  char* ok = fgets(buffer, 255, status);
                  if (!ok)
                     break;

                  if (String_startsWith(buffer, "VxID:")) {
                     int vxid;
                     int ok = ProcessList_read(this, buffer, "VxID:\t%d", &vxid);
                     if (ok >= 1) {
                        process->vxid = vxid;
                     }
                  }
                  #if defined HAVE_ANCIENT_VSERVER
                  else if (String_startsWith(buffer, "s_context:")) {
                     int vxid;
                     int ok = ProcessList_read(this, buffer, "s_context:\t%d", &vxid);
                     if (ok >= 1) {
                        process->vxid = vxid;
                     }
                  }
                  #endif
               }
               fclose(status);
            }
            #endif
 
            snprintf(statusfilename, MAX_NAME, "%s/%s/cmdline", dirname, name);
            status = ProcessList_fopen(this, statusfilename, "r");
            if (!status) {
               goto errorReadingProcess;
            }

            int amtRead = fread(command, 1, PROCESS_COMM_LEN - 1, status);
            if (amtRead > 0) {
               for (int i = 0; i < amtRead; i++)
                  if (command[i] == '\0' || command[i] == '\n')
                     command[i] = ' ';
               command[amtRead] = '\0';
            }
            command[PROCESS_COMM_LEN] = '\0';
            process->comm = String_copy(command);
            fclose(status);
         }

         int percent_cpu = (process->utime + process->stime - lasttimes) / 
            period * 100.0;
         process->percent_cpu = MAX(MIN(percent_cpu, processors*100.0), 0.0);

         process->percent_mem = (process->m_resident * PAGE_SIZE_KB) / 
            (float)(this->totalMem) * 
            100.0;

         /*this->totalTasks++;*/
         if (process->state == 'R') {
            this->runningTasks++;
         }

         if (!existingProcess) {
            process = Process_clone(process);
            ProcessList_add(this, process);
         }

         continue;

         // Exception handler.
         errorReadingProcess: {
            if (process->comm) {
               free(process->comm);
               process->comm = NULL;
            }
            if (existingProcess)
               ProcessList_remove(this, process);
            assert(Hashtable_count(this->processTable) == Vector_count(this->processes));
         }
      }
   }
   closedir(dir);
   return true;
}

void ProcessList_scan(ProcessList* this) {
   unsigned long long int usertime, nicetime, systemtime, 
                 systemalltime, idlealltime, idletime, totaltime;

   mach_msg_type_number_t infoCount;
   vm_statistics_data_t   vm_stat;

   infoCount = sizeof(vm_statistics_data_t) / sizeof(integer_t);

   noerr(host_statistics(mach_host_self(), HOST_VM_INFO,
                           (host_info_t) &vm_stat, &infoCount));

/*
   free_count;
   active_count;
   inactive_count;
   wire_count;
   zero_fill_count;
   reactivations;
   pageins;
   pageouts;
   faults;
   cow_faults;
   lookups;
   hits;
*/

   this->freeMem    = this->pageSize * vm_stat.free_count / 1024;
   this->sharedMem  = 0;
   this->buffersMem = 0;
   this->cachedMem  = 0;
   this->totalSwap  = 0;
   this->freeSwap   = 0;

   this->usedMem  = this->totalMem  - this->freeMem;
   this->usedSwap = this->totalSwap - this->freeSwap;

   unsigned int cpu_count;
   processor_cpu_load_info_t cpu_load;
   mach_msg_type_number_t cpu_msg_count;

   noerr(host_processor_info(mach_host_self(), PROCESSOR_CPU_LOAD_INFO,
                           &cpu_count,
                           (processor_info_array_t *)&cpu_load,
                           &cpu_msg_count));

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

   for (int i = 1; i <= cpu_count; i++) {
      unsigned long long int ioWait, irq, softIrq, steal;

      usertime   = cpu_load[i-1].cpu_ticks[CPU_STATE_USER];
      nicetime   = cpu_load[i-1].cpu_ticks[CPU_STATE_NICE];
      systemtime = cpu_load[i-1].cpu_ticks[CPU_STATE_SYSTEM];
      idletime   = cpu_load[i-1].cpu_ticks[CPU_STATE_IDLE];
      ioWait     = 0;
      irq        = 0;
      softIrq    = 0;
      steal      = 0;

      idlealltime = idletime + ioWait;
      systemalltime = systemtime + irq + softIrq + steal;
      totaltime = usertime + nicetime + systemalltime + idlealltime;

      UPSLOT( userPeriod,      usertime - this->userTime[i] );
      UPSLOT( nicePeriod,      nicetime - this->niceTime[i] );
      UPSLOT( systemPeriod,    systemtime - this->systemTime[i] );
      UPSLOT( systemAllPeriod, systemalltime - this->systemAllTime[i] );
      UPSLOT( idleAllPeriod,   idlealltime - this->idleAllTime[i] );
      UPSLOT( idlePeriod,      idletime - this->idleTime[i] );
      UPSLOT( ioWaitPeriod,    ioWait - this->ioWaitTime[i] );
      UPSLOT( irqPeriod,       irq - this->irqTime[i] );
      UPSLOT( softIrqPeriod,   softIrq - this->softIrqTime[i] );
      UPSLOT( stealPeriod,     steal - this->stealTime[i] );
      UPSLOT( totalPeriod,     totaltime - this->totalTime[i] );
      UPSLOT( userTime,        usertime );
      UPSLOT( niceTime,        nicetime );
      UPSLOT( systemTime,      systemtime );
      UPSLOT( systemAllTime,   systemalltime );
      UPSLOT( idleAllTime,     idlealltime );
      UPSLOT( idleTime,        idletime );
      UPSLOT( ioWaitTime,      ioWait );
      UPSLOT( irqTime,         irq );
      UPSLOT( softIrqTime,     softIrq );
      UPSLOT( stealTime,       steal );
      UPSLOT( totalTime,       totaltime );
   }

   vm_deallocate(mach_task_self(),
                  (vm_address_t)cpu_load,
                  (vm_size_t)(cpu_msg_count * sizeof(*cpu_load)));

   float period = (float)this->totalPeriod[0] / cpu_count;

   // mark all process as "dirty"
   for (int i = 0; i < Vector_size(this->processes); i++) {
      Process* p = (Process*) Vector_get(this->processes, i);
      p->updated = false;
   }
   
   this->totalTasks = 0;
   this->runningTasks = 0;

   ProcessList_processEntries(this, PROCDIR, NULL, period);
   ProcessList_getProcesses(this, period);
   
   for (int i = Vector_size(this->processes) - 1; i >= 0; i--) {
      Process* p = (Process*) Vector_get(this->processes, i);
      if (p->updated == false)
         ProcessList_remove(this, p);
      else
         p->updated = false;
   }

}

ProcessField ProcessList_keyAt(ProcessList* this, int at) {
   int x = 0;
   ProcessField* fields = this->fields;
   ProcessField field;
   for (int i = 0; (field = fields[i]); i++) {
      int len = strlen(Process_fieldTitles[field]);
      if (at >= x && at <= x + len) {
         return field;
      }
      x += len;
   }
   return COMM;
}
