#define _GNU_SOURCE

#include <stdio.h>
#include <time.h>
#include <dlfcn.h>

/*
	Daniel Chrostowski
	dc1036
	164006794
*/

time_t time(time_t *tloc){	//returns the time in seconds since the Epoch, 1970-01-01 00:00:00 +0000 (UTC)
	
	// bit to see if first time that time() is called
	int first_time = 1;

	// PART 1: use custom time() set a fake time so that the time can be verified within the time frame
	
	// if tloc is non-NULL, the return value is stored in memory location pointed to by tloc
	// first check if tloc is NULL or not...
	if(tloc == NULL){
		return 0;
	}
	// if tloc is not NULL then set the value stored inside tloc to a custom time (I chose Jan 4, 2016)
	if(first_time == 1){
		first_time = 0;
				
		if(tloc != NULL && *tloc == 0){
			time_t customTime = 1451910600;
			*tloc = customTime;	
			return *tloc;
		} 
	} 
	// PART 2: set the time function back to the C library version instead of custom time function
	if(first_time != 1) {
		time_t (*original_time)(time_t *tloc);
		original_time = dlsym(RTLD_NEXT, "time");
		return original_time(tloc);
	}	

	return 0;

}

