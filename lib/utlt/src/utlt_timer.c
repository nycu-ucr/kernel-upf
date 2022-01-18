#include "utlt_timer.h"

#include <string.h>
#include <stdio.h>

#include "utlt_debug.h"
#include "utlt_pool.h"

//static int TimerCmpFunc(ListHead *pnode1, ListHead *pnode2);

typedef struct _TimerBlk {
    ListHead        node;
    TimerList       *timerList;
    
    int             type;
    int             isRunning;
    int32_t         expireTime;
    uint32_t        duration;
    
    ExpireFunc      expireFunc;
    uintptr_t       param[6];
} TimerBlk;

PoolDeclare(timerPool, TimerBlk, MAX_NUM_OF_TIMER);

// static int TimerCmpFunc(ListHead *pnode1, ListHead *pnode2) {
//     TimerBlk *tm1 = (TimerBlk *)pnode1;
//     TimerBlk *tm2 = (TimerBlk *)pnode2;

//     return (tm1->expireTime < tm2->expireTime ? -1 : 1);
// }

Status TimerPoolInit() {
    PoolInit(&timerPool, MAX_NUM_OF_TIMER);
    return STATUS_OK;
}

Status TimerFinal() {
    if (PoolCap(&timerPool) != PoolSize(&timerPool))
        UTLT_Error("%d not freed in timerPool[%d]",
            PoolCap(&timerPool) - PoolSize(&timerPool), PoolCap(&timerPool));
    
    PoolTerminate(&timerPool);

    return STATUS_OK;
}

uint32_t TimerGetPoolSize() {
    // The number of available space in this pool
    return PoolSize(&timerPool);
}

void TimerListInit(TimerList *tmList) {
    memset(tmList, 0, sizeof(TimerList));
    ListHeadInit(&tmList->active);
    ListHeadInit(&tmList->idle);
    pthread_mutex_init(&tmList->lock, 0);
    return;
}

// Check expire time and update active and idle list
Status TimerExpireCheck(TimerList *tmList, uintptr_t data, int32_t diff) {
    //uint32_t curTime;
    TimerBlk *tm, *next = NULL;

    pthread_mutex_lock(&tmList->lock);
    if (ListIsEmpty(&tmList->active)) {
        UTLT_Error("TimerExpireCheck: Empty");
        goto out;
    }

    UTLT_Error("TimerExpireCheck: Entry");

    //curTime = TimeMsec(TimeNow());
      
    ListForEachSafe(tm, next, &tmList->active) {
        if (!tm->isRunning) 
            continue;

        if (tm->expireTime < 0) {
            tm->expireFunc(data, tm->param);
    
            if (tm->type == TIMER_TYPE_PERIOD) {
                tm->expireTime = tm->duration;
                //ListInsertSorted(tm, &(tmList->active), TimerCmpFunc);
            } else {
               //ListInsertSorted(tm, &(tmList->idle), TimerCmpFunc);
                tm->isRunning = 0;
            }
       } else {
           tm->expireTime -= diff;
       }
    }
   
out:
    UTLT_Error("TimerExpireCheck: Exit");
    pthread_mutex_unlock(&tmList->lock);
    return STATUS_OK;
}

// TimerBlk put into "active" list
Status TimerStart(TimerBlkID id) {
    TimerBlk *tm = (TimerBlk *)id;
    //uint32_t curTime;

    pthread_mutex_lock(&tm->timerList->lock);
    //curTime = TimeMsec(TimeNow());
    //ListRemove(tm);
    //tm->expireTime = curTime + tm->duration;
    tm->expireTime = tm->duration;
    //ListInsertSorted(tm, &(tm->timerList->active), TimerCmpFunc);
    ListInsertTail(tm, &(tm->timerList->active));
    tm->isRunning = 1;
    pthread_mutex_unlock(&tm->timerList->lock);

    return STATUS_OK;
}

// TimerBlk put into "idle" list
Status TimerStop(TimerBlkID id) {
    TimerBlk *tm = (TimerBlk *) id;

    pthread_mutex_lock(&tm->timerList->lock);
    if (tm->isRunning) {
        ListRemove(tm);
        //ListInsertSorted(tm, &(tm->timerList->idle), TimerCmpFunc);
        tm->isRunning = 0;
    }
    pthread_mutex_unlock(&tm->timerList->lock);

    return STATUS_OK;
}

// TimerBlk put into "idle" list
TimerBlkID TimerCreate(TimerList *tmList, int type, uint32_t duration, ExpireFunc expireFunc) {
    TimerBlk *tm = NULL;
    
    PoolAlloc(&timerPool, tm);
    UTLT_Assert(tm, return (TimerBlkID) NULL, "TimerCreate: Timer pool is empty");
    
    memset((char *) tm, 0, sizeof(TimerBlk));

    pthread_mutex_lock(&tmList->lock);
    tm->timerList = tmList;
    ListHeadInit(&tm->node);
    //ListInsertSorted(tm, &(tm->timerList->idle), TimerCmpFunc);
    tm->type = type;
    tm->duration = duration;
    tm->expireFunc = expireFunc;
    pthread_mutex_unlock(&tmList->lock);

    return (TimerBlkID) tm;
}

// TimerBlk freed
void TimerDelete(TimerBlkID id) {
    TimerBlk *tm = (TimerBlk *) id;

    pthread_mutex_lock(&tm->timerList->lock);
    ListRemove(tm);
    pthread_mutex_unlock(&tm->timerList->lock);

    PoolFree(&timerPool, tm);
    
    return;
}

Status TimerSet(int paramID, TimerBlkID id, uintptr_t param) {
    TimerBlk *tm = (TimerBlk *)id;

    UTLT_Assert(paramID >= 0 && paramID < 6, return STATUS_ERROR, 
        "TimerSet: Wrong paramID for setting timer parameter");
    tm->param[paramID] = param;
    
    return STATUS_OK;
}
