/*
  htop
  (C) 2004-2006 Hisham H. Muhammad
  Released under the GNU GPL, see the COPYING file
  in the source distribution for its full text.

  This "Meter" written by Ian P. Hands (iphands@gmail.com, ihands@redhat.com).
*/

#include "BatteryMeter.h"
#include "Meter.h"
#include "ProcessList.h"
#include "CRT.h"
#include "String.h"
#include "debug.h"

/*{

typedef enum ACPresence_ {
   AC_ABSENT,
   AC_PRESENT,
   AC_ERROR
} ACPresence;

}*/

int BatteryMeter_attributes[] = {
   BATTERY
};

static unsigned long int parseUevent(FILE * file, char *key) {
   char line[100];
   unsigned long int dValue = 0;

   while (fgets(line, sizeof line, file)) {
      if (strncmp(line, key, strlen(key)) == 0) {
         char *value;
         value = strtok(line, "=");
         value = strtok(NULL, "=");
         dValue = atoi(value);
         break;
      }
   }
   return dValue;
}

static ACPresence chkIsOnline() {
   FILE *file = NULL;
   ACPresence isOn = AC_ERROR;

   return isOn;
}

static double getProcBatData() {
   return 100;
}

static double getSysBatData() {
   const struct dirent *dirEntries;
   char *power_supplyPath = "/sys/class/power_supply/";
   DIR *power_supplyDir = opendir(power_supplyPath);


   if (!power_supplyDir) {
      closedir(power_supplyDir);
      return 0;
   }

   char *entryName;

   unsigned long int totalFull = 0;
   unsigned long int totalRemain = 0;

   for (dirEntries = readdir((DIR *) power_supplyDir); dirEntries; dirEntries = readdir((DIR *) power_supplyDir)) {
      entryName = (char *) dirEntries->d_name;

      if (strncmp(entryName, "BAT", 3)) {
         continue;
      }

      const char ueventPath[50];

      snprintf((char *) ueventPath, sizeof ueventPath, "%s%s/uevent", power_supplyPath, entryName);

      FILE *file;
      if ((file = fopen(ueventPath, "r")) == NULL) {
         closedir(power_supplyDir);
         return 0;
      }

      totalFull += parseUevent(file, "POWER_SUPPLY_ENERGY_FULL=");
      totalRemain += parseUevent(file, "POWER_SUPPLY_ENERGY_NOW=");
      fclose(file);
   }

   const double percent = totalFull > 0 ? ((double) totalRemain * 100) / (double) totalFull : 0;
   closedir(power_supplyDir);
   return percent;
}

static void BatteryMeter_setValues(Meter * this, char *buffer, int len) {
   double percent = getProcBatData();
   if (percent == 0) {
      percent = getSysBatData();
      if (percent == 0) {
         snprintf(buffer, len, "n/a");
         return;
      }
   }

   this->values[0] = percent;

   char *onAcText, *onBatteryText, *unknownText;

   unknownText = "%.1f%%";
   if (this->mode == TEXT_METERMODE) {
      onAcText = "%.1f%% (Running on A/C)";
      onBatteryText = "%.1f%% (Running on battery)";
   } else {
      onAcText = "%.1f%%(A/C)";
      onBatteryText = "%.1f%%(bat)";
   }

   ACPresence isOnLine = chkIsOnline();

   if (isOnLine == AC_PRESENT) {
      snprintf(buffer, len, onAcText, percent);
   } else if (isOnLine == AC_ABSENT) {
      snprintf(buffer, len, onBatteryText, percent);
   } else {
      snprintf(buffer, len, unknownText, percent);
   }

   return;
}

MeterType BatteryMeter = {
   .setValues = BatteryMeter_setValues,
   .display = NULL,
   .mode = TEXT_METERMODE,
   .items = 1,
   .total = 100.0,
   .attributes = BatteryMeter_attributes,
   .name = "Battery",
   .uiName = "Battery",
   .caption = "Battery: "
};
