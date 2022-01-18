#ifndef __UPF_TIMER_H__
#define __UPF_TIMER_H__

#include <signal.h> 
#include <time.h>   


typedef void (*handler)(union sigval sv);

int UpfCreateAndStartTimer(timer_t *timerid, handler hdl, time_t time, void *arg);
void UpfDeleteTimer(timer_t *timerid);
void UpfModifyTimerInSec(timer_t *timerid, time_t time);
void UpfModifyTimerInNS(timer_t *timerid, long time);

#endif