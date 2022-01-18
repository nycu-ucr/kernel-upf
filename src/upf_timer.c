#include <string.h>

#include "upf_timer.h"

int UpfCreateAndStartTimer(timer_t *timerid, handler hdl, time_t time, void *arg) {   
    struct sigevent sev;
    struct itimerspec trigger;

    memset(&sev, 0, sizeof(struct sigevent));
    memset(&trigger, 0, sizeof(struct itimerspec));

    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_notify_function = hdl;
    sev.sigev_value.sival_ptr = arg;

    timer_create(CLOCK_REALTIME, &sev, timerid);

    trigger.it_value.tv_sec = time;
    timer_settime(timerid, 0, &trigger, NULL);

    return 0;
}

void UpfDeleteTimer(timer_t *timerid) {
    timer_delete(timerid);
}

void UpfModifyTimerInSec(timer_t *timerid, time_t time) {
    struct itimerspec trigger;
    
    memset(&trigger, 0, sizeof(struct itimerspec));
    trigger.it_value.tv_sec = time;
    timer_settime(timerid, 0, &trigger, NULL);
}

void UpfModifyTimerInNS(timer_t *timerid, long time) {
    struct itimerspec trigger;
    
    memset(&trigger, 0, sizeof(struct itimerspec));
    trigger.it_value.tv_nsec = time;
    timer_settime(timerid, 0, &trigger, NULL);
}