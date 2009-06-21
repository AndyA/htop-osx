/*
htop
(C) 2004-2006 Hisham H. Muhammad
Released under the GNU GPL, see the COPYING file
in the source distribution for its full text.
*/

#include "UptimeMeter.h"
#include "Meter.h"

#include "ProcessList.h"

#include "CRT.h"

#include "debug.h"

#include <sys/sysctl.h>

int UptimeMeter_attributes[] = {
   UPTIME
};

static void UptimeMeter_setValues(Meter* this, char* buffer, int len) {
   int mib[2];
   size_t size;
   time_t uptime;
   struct timeval boottime;
   time_t now;

   mib[0] = CTL_KERN;
   mib[1] = KERN_BOOTTIME;
   size = sizeof(boottime);
   (void) time(&now);
   if (sysctl(mib, 2, &boottime, &size, NULL, 0) != -1 
         && boottime.tv_sec != 0) {
      uptime = now - boottime.tv_sec;
      int totalseconds = (int) uptime;
      int seconds = totalseconds % 60;
      int minutes = (totalseconds/60) % 60;
      int hours = (totalseconds/3600) % 24;
      int days = (totalseconds/86400);
      this->values[0] = days;
      if (days > this->total) {
         this->total = days;
      }
      char daysbuf[15];
      if (days > 100) {
         sprintf(daysbuf, "%d days(!), ", days);
      } else if (days > 1) {
         sprintf(daysbuf, "%d days, ", days);
      } else if (days == 1) {
         sprintf(daysbuf, "1 day, ");
      } else {
         daysbuf[0] = '\0';
      }
      snprintf(buffer, len, "%s%02d:%02d:%02d", daysbuf, hours, minutes, seconds);
   }
   else {
      snprintf(buffer, len, "???");
   }
}

MeterType UptimeMeter = {
   .setValues = UptimeMeter_setValues, 
   .display = NULL,
   .mode = TEXT_METERMODE,
   .items = 1,
   .total = 100.0,
   .attributes = UptimeMeter_attributes,
   .name = "Uptime",
   .uiName = "Uptime",
   .caption = "Uptime: "
};
