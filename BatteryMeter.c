/*
  htop
  (C) 2004-2006 Hisham H. Muhammad
  Released under the GNU GPL, see the COPYING file
  in the source distribution for its full text.

  This "Meter" written by Ian P. Hands (iphands@gmail.com, ihands@redhat.com).
  Adapted for OSX by Jonas Due Vesterheden (jonasduevesterheden@gmail.com)
*/

#include <CoreFoundation/CoreFoundation.h>
#include <CoreFoundation/CFString.h>
#include <IOKit/ps/IOPowerSources.h>
#include <IOKit/ps/IOPSKeys.h>

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

static ACPresence chkIsOnline() {
   CFTypeRef sourceInfo = IOPSCopyPowerSourcesInfo();
   CFArrayRef sourceList = IOPSCopyPowerSourcesList(sourceInfo);

   // Loop through sources, find the first battery
   int count = CFArrayGetCount(sourceList);
   CFDictionaryRef source = NULL;
   for(int i=0; i < count; i++) {
      source = IOPSGetPowerSourceDescription(sourceInfo, CFArrayGetValueAtIndex(sourceList, i));

      // Is this a battery?
      CFStringRef type = (CFStringRef)CFDictionaryGetValue(source, CFSTR(kIOPSTransportTypeKey));
      if(kCFCompareEqualTo == CFStringCompare(type, CFSTR(kIOPSInternalType), 0)) {
         break;
      }
   }

   ACPresence isOn = AC_ERROR;
   if(source != NULL) {
      CFStringRef state = CFDictionaryGetValue(source, CFSTR(kIOPSPowerSourceStateKey));
      if(kCFCompareEqualTo == CFStringCompare(state, CFSTR(kIOPSACPowerValue), 0)) {
         isOn = AC_PRESENT;
      } else {
         isOn = AC_ABSENT;
      }
   }

   CFRelease(sourceInfo);
   CFRelease(sourceList);
   return isOn;
}

static double getBatData() {
   CFTypeRef sourceInfo = IOPSCopyPowerSourcesInfo();
   CFArrayRef sourceList = IOPSCopyPowerSourcesList(sourceInfo);

   // Loop through sources, find the first battery
   int count = CFArrayGetCount(sourceList);
   CFDictionaryRef source = NULL;
   for(int i=0; i < count; i++) {
      source = IOPSGetPowerSourceDescription(sourceInfo, CFArrayGetValueAtIndex(sourceList, i));

      // Is this a battery?
      CFStringRef type = (CFStringRef)CFDictionaryGetValue(source, CFSTR(kIOPSTransportTypeKey));
      if(kCFCompareEqualTo == CFStringCompare(type, CFSTR(kIOPSInternalType), 0)) {
         break;
      }
   }

   float percent = 0;
   if(source != NULL) {
      int curCapacity;
      CFNumberGetValue(CFDictionaryGetValue(source, CFSTR(kIOPSCurrentCapacityKey)), kCFNumberIntType, &curCapacity);

      int maxCapacity;
      CFNumberGetValue(CFDictionaryGetValue(source, CFSTR(kIOPSMaxCapacityKey)), kCFNumberIntType, &maxCapacity);

      percent = curCapacity / (float)maxCapacity*100.f;
   }

   CFRelease(sourceInfo);
   CFRelease(sourceList);
   return percent;
}

static void BatteryMeter_setValues(Meter * this, char *buffer, int len) {
   double percent = getBatData();
   if (percent == 0) {
     snprintf(buffer, len, "n/a");
     return;
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
