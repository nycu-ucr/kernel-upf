#define TRACE_MODULE _pfcp_xact

#include <endian.h>

#include "utlt_debug.h"
#include "utlt_pool.h"
#include "utlt_3gppTypes.h"
#include "utlt_index.h"
#include "utlt_timer.h"
#include "utlt_event.h"

#include "pfcp_types.h"
#include "pfcp_message.h"
#include "pfcp_path.h"

#include "pfcp_xact.h"

#define SIZE_OF_PFCP_XACT_POOL          2048
#define PFCP_MIN_XACT_ID                1
#define PFCP_MAX_XACT_ID                0x800000

#define PFCP_T3_RESPONSE_DURATION       2000 
#define PFCP_T3_RESPONSE_RETRY_COUNT    2
#define PFCP_T3_DUPLICATED_DURATION \
    (PFCP_T3_RESPONSE_DURATION * PFCP_T3_RESPONSE_RETRY_COUNT)  /* 4 seconds */
#define PFCP_T3_DUPLICATED_RETRY_COUNT  1


static int pfcpXactInitialized = 0; // if xact exist
static TimerList *globalTimerList = NULL;
static uint32_t globalXactId = 0;

IndexDeclare(pfcpXactPool, PfcpXact, SIZE_OF_PFCP_XACT_POOL);

Status PfcpXactInit(TimerList *timerList, uintptr_t responseEvent, uintptr_t holdingEvent) {
    UTLT_Assert(pfcpXactInitialized == 0, return STATUS_ERROR, "XactInit: Already initialized");
    IndexInit(&pfcpXactPool, SIZE_OF_PFCP_XACT_POOL);

    globalXactId = 0;
    globalTimerList = timerList;
   
    pfcpXactInitialized = 1;

    return STATUS_OK;
}

Status PfcpXactTerminate() {
    UTLT_Assert(pfcpXactInitialized == 1, return STATUS_ERROR,
                "XactTerminate: PFCP Xact either already terminated or not initialized");

    if (PoolUsedCheck(&pfcpXactPool)) {
        UTLT_Warning("XactTerminate: %d not freed %d of pfcpXactPool",
            PoolUsedCheck(&pfcpXactPool), PoolSize(&pfcpXactPool));
    }
    UTLT_Warning("XactTerminate: %d freed %d of pfcpXactPool",
        PoolUsedCheck(&pfcpXactPool), PoolSize(&pfcpXactPool));

    IndexTerminate(&pfcpXactPool);
    pfcpXactInitialized = 0;

    return STATUS_OK;
}

PfcpXact *PfcpXactLocalCreate(PfcpNode *gnode, PfcpHeader *header, Bufblk *bufBlk) {
    Status status;
    PfcpXact *xact = NULL;

    UTLT_Assert(gnode, return NULL, "XactLocalCreate: - node NULL");

    IndexAlloc(&pfcpXactPool, xact);
    UTLT_Assert(xact, return NULL, "XactLocalCreate: Failed to create xact");

    xact->origin = PFCP_LOCAL_ORIGINATOR;
    xact->transactionId = (globalXactId == PFCP_MAX_XACT_ID ? PFCP_MIN_XACT_ID : ++globalXactId);
    xact->gnode = gnode;

    ListInsert(xact, &xact->gnode->localList);
   
    status = PfcpXactUpdateTx(xact, header, bufBlk);
    UTLT_Assert(status == STATUS_OK, goto err, "XactLocalCreate: Failed to update xact Tx");

    UTLT_Trace("XactLocalCreate: XID: %d O: %s Create P: %s:%d\n",
        xact->transactionId, 
        xact->origin == PFCP_LOCAL_ORIGINATOR ? "local" : "remote",
        GetIP(&gnode->sock->remoteAddr), 
        GetPort(&gnode->sock->remoteAddr));

    return xact;
err:
    IndexFree(&pfcpXactPool, xact);
    return NULL;
}

PfcpXact *PfcpXactRemoteCreate(PfcpNode *gnode, uint32_t sqn) {
    PfcpXact *xact = NULL;

    UTLT_Assert(gnode, goto err, "XactRemoteCeate: node NULL");

    IndexAlloc(&pfcpXactPool, xact);
    UTLT_Assert(xact, goto err, "XactRemoteCeate: Failed to allocate Xact");

    xact->origin = PFCP_REMOTE_ORIGINATOR;
    xact->transactionId = PfcpSqn2TransactionId(sqn);
    xact->gnode = gnode;
   
    ListInsert(xact, &gnode->remoteXactList);
   
    UTLT_Debug("XactRemoteCeate: Created XID: %d O: %s P: %s:%d\n", 
        xact->transactionId, 
        xact->origin == PFCP_LOCAL_ORIGINATOR ? "local " : "remote",
        GetIP(&gnode->sock->remoteAddr), 
        GetPort(&gnode->sock->remoteAddr));

    return xact;

err:
    return NULL;
}

void PfcpXactDeassociate(PfcpXact *xact1, PfcpXact *xact2) {
    UTLT_Assert(xact1, return, "XactDeass: xact1 NULL");
    UTLT_Assert(xact2, return, "XactDeass: xact2 NULL");

    UTLT_Assert(xact1->associatedXact != NULL, return, "XactDeass: 1 Already deassocaited");
    UTLT_Assert(xact2->associatedXact != NULL, return, "XactDeass: 2 Already deassocaited");

    xact1->associatedXact = NULL;
    xact2->associatedXact = NULL;
    return;
}

Status PfcpXactDelete(PfcpXact *xact) {
    UTLT_Assert(xact, , "XactDel: xact NULL");
    UTLT_Assert(xact->gnode, , "XactDel: node NULL");

    UTLT_Debug("XactDel: Deleted XID: %d O: %s P: %s:%d\n", 
        xact->transactionId,
        xact->origin == PFCP_LOCAL_ORIGINATOR ? "local" : "remote",
        GetIP(&xact->gnode->sock->remoteAddr), 
        GetPort(&xact->gnode->sock->remoteAddr));
            
    //FIXME: always true?
    if (xact->origin == PFCP_LOCAL_ORIGINATOR || PFCP_REMOTE_ORIGINATOR) {
        //TODO: Protect the list by locking
        ListRemove(xact);
    } else {
        UTLT_Warning("XactDel: Unknown XID: %d O: %d", 
            xact->transactionId, xact->origin);
    }

    xact->origin = 0;
    xact->transactionId = 0;
    xact->step = 0;
    xact->seq[0].type = 0;
    xact->seq[1].type = 0;
    xact->seq[2].type = 0;

    if (xact->seq[0].bufBlk) {
        BufblkFree(xact->seq[0].bufBlk);
    }
    if (xact->seq[1].bufBlk) {
        BufblkFree(xact->seq[1].bufBlk);
    }
    if (xact->seq[2].bufBlk) {
        BufblkFree(xact->seq[2].bufBlk);
    }

    if (xact->associatedXact) {
        PfcpXactDeassociate(xact, xact->associatedXact);
    }

    IndexFree(&pfcpXactPool, xact);

    return STATUS_OK;
}

void PfcpXactDeleteAll(PfcpNode *gnode) {
    PfcpXact *xact, *nextNode = NULL;
    
    ListForEachSafe(xact, nextNode, &gnode->localList) {
        PfcpXactDelete(xact);
    }

    ListForEachSafe(xact, nextNode, &gnode->remoteXactList) {
        PfcpXactDelete(xact);
    }

    return;
}

static PfcpXactStage PfcpXactGetStage(uint8_t type, uint32_t transactionId) {
    PfcpXactStage stage = PFCP_XACT_UNKNOWN_STAGE;

    switch (type) {
    case PFCP_HEARTBEAT_REQUEST:
    case PFCP_ASSOCIATION_SETUP_REQUEST:
    case PFCP_ASSOCIATION_UPDATE_REQUEST:
    case PFCP_ASSOCIATION_RELEASE_REQUEST:
    case PFCP_SESSION_ESTABLISHMENT_REQUEST:
    case PFCP_SESSION_MODIFICATION_REQUEST:
    case PFCP_SESSION_DELETION_REQUEST:
    case PFCP_SESSION_REPORT_REQUEST:
        stage = PFCP_XACT_INITIAL_STAGE;
        break;
    case PFCP_HEARTBEAT_RESPONSE:
    case PFCP_ASSOCIATION_SETUP_RESPONSE:
    case PFCP_ASSOCIATION_UPDATE_RESPONSE:
    case PFCP_ASSOCIATION_RELEASE_RESPONSE:
    case PFCP_VERSION_NOT_SUPPORTED_RESPONSE:
    case PFCP_SESSION_ESTABLISHMENT_RESPONSE:
    case PFCP_SESSION_MODIFICATION_RESPONSE:
    case PFCP_SESSION_DELETION_RESPONSE:
    case PFCP_SESSION_REPORT_RESPONSE:
        stage = PFCP_XACT_FINAL_STAGE;
        break;
    default:
        UTLT_Error("XactGetStage: Not implemented PFCP Message Type: %d", type);
        break;
    }

    return stage;
}

Status PfcpXactUpdateTx(PfcpXact *xact, PfcpHeader *header, Bufblk *bufBlk) {
    PfcpXactStage stage;
    PfcpHeader *localHeader = NULL;
    uint8_t headerLen = 0;
    Bufblk *fullPacket;

    UTLT_Assert(xact, return STATUS_ERROR, "XactUpTx: xact NULL");
    UTLT_Assert(xact->gnode, return STATUS_ERROR, "XactUpTx: node NULL");
    UTLT_Assert(header, return STATUS_ERROR, "XactUpTx: header NULL");
    UTLT_Assert(bufBlk, return STATUS_ERROR, "XactUpTx: buffer NULL");

    UTLT_Trace("XactUpTx: XID: %d O: %s T: %d P: %s:%d\n",
        xact->transactionId, 
        xact->origin == PFCP_LOCAL_ORIGINATOR ? "local " : "remote",
        header->type, GetIP(&xact->gnode->sock->remoteAddr),
        GetPort(&xact->gnode->sock->remoteAddr));

    stage = PfcpXactGetStage(header->type, xact->transactionId);
    if (xact->origin == PFCP_LOCAL_ORIGINATOR) {
        switch (stage) {
        case PFCP_XACT_INITIAL_STAGE:
            UTLT_Assert(xact->step == 0, return STATUS_ERROR,
                "XactUpTx: XID: %d O: %s invalid S: %d T: %d P: %s:%d\n",
                xact->transactionId, xact->origin == PFCP_LOCAL_ORIGINATOR ?
                "local " : "remote", xact->step, header->type,
                GetIP(&xact->gnode->sock->remoteAddr),
                GetPort(&xact->gnode->sock->remoteAddr));
            break;
        case PFCP_XACT_INTERMEDIATE_STAGE:
            UTLT_Assert(0, return STATUS_ERROR, "XactUpTx:  XID: %d invalid S: %d in local", 
                xact->transactionId, xact->step);
            break;
        case PFCP_XACT_FINAL_STAGE:
            UTLT_Assert(xact->step == 2, return STATUS_ERROR,
                "XactUpTx: XID: %d O: %s invalid S: %d for T: %d P: %s:%d\n",
                xact->transactionId, 
                xact->origin == PFCP_LOCAL_ORIGINATOR ? "local " : "remote", 
                xact->step, header->type,
                GetIP(&xact->gnode->sock->remoteAddr),
                GetPort(&xact->gnode->sock->remoteAddr));
            break;
        default:
            UTLT_Assert(0, return STATUS_ERROR, "XactUpTx: XID: %d invalid S: %d in local", 
                xact->transactionId, xact->step);
        }
    } else if (xact->origin == PFCP_REMOTE_ORIGINATOR) {
        switch (stage) {
        case PFCP_XACT_INITIAL_STAGE:
            UTLT_Assert(0, return STATUS_ERROR, "XactUpTx: XID: %d invalid S: %d in remote", 
                xact->transactionId, xact->step);
            break;
        case PFCP_XACT_INTERMEDIATE_STAGE:
        case PFCP_XACT_FINAL_STAGE:
            UTLT_Assert(xact->step == 1, return STATUS_ERROR,
                        "XactUpTx: XID: %d O: %s invalid S: %d for T: %d P: %s:%d\n",
                        xact->transactionId, xact->origin == PFCP_LOCAL_ORIGINATOR ?
                        "local " : "remote", xact->step, header->type,
                        GetIP(&xact->gnode->sock->remoteAddr),
                        GetPort(&xact->gnode->sock->remoteAddr));
            break;
        default:
            UTLT_Assert(0, return STATUS_ERROR, "XactUpTx: XID: %d invalid S: %d in remote", 
                xact->transactionId, xact->step);
        }
    } else {
        UTLT_Assert(0, return STATUS_ERROR, "XactUpTx: XID: %d invalid O: %d", 
            xact->transactionId, xact->origin);
    }

    if (header->type >= PFCP_SESSION_ESTABLISHMENT_REQUEST) { // with SEID
        headerLen = PFCP_HEADER_LEN;
    } else { // no SEID
        headerLen = PFCP_HEADER_LEN - PFCP_SEID_LEN;
    }

    fullPacket = BufblkAlloc(1, headerLen);
    localHeader = fullPacket->buf;
    fullPacket->len = headerLen;

    memset(localHeader, 0, headerLen);
    localHeader->version = PFCP_VERSION;
    localHeader->type = header->type;
    if(header->type >= PFCP_SESSION_ESTABLISHMENT_REQUEST) { // with SEID
        localHeader->seidP = 1;
        localHeader->seid = htobe64(header->seid);
        localHeader->sqn = PfcpTransactionId2Sqn(xact->transactionId);
        // For SRR,
        header->sqn = localHeader->sqn;
    } else { // no SEID
        localHeader->seidP = 0;
        localHeader->sqn_only = PfcpTransactionId2Sqn(xact->transactionId);
    }

    localHeader->length = htons(bufBlk->len + headerLen - 4);

    BufblkBuf(fullPacket, bufBlk);
    BufblkFree(bufBlk);

    xact->seq[xact->step].type = localHeader->type;
    xact->seq[xact->step].bufBlk = fullPacket;
    xact->step++;

    return STATUS_OK;
}

Status PfcpXactUpdateRx(PfcpXact *xact, uint8_t type) {
    Status status = STATUS_OK;
    PfcpXactStage stage;

    UTLT_Trace("XactUpRx: XID: %d O: %s T: %d P: %s:%d\n", 
        xact->transactionId,
        xact->origin == PFCP_LOCAL_ORIGINATOR ? "local " : "remote",
        type, GetIP(&xact->gnode->sock->remoteAddr),
        GetPort(&xact->gnode->sock->remoteAddr) );

    stage = PfcpXactGetStage(type, xact->transactionId);
    if (xact->origin == PFCP_LOCAL_ORIGINATOR) {
        switch (stage) {
        case PFCP_XACT_INITIAL_STAGE:
            UTLT_Assert(0, return STATUS_ERROR, "XactUpRx: XID: %d invalid S: %d in local", 
                xact->transactionId, xact->step);
            break;
        case PFCP_XACT_INTERMEDIATE_STAGE:
            if (xact->seq[1].type == type) {
                Bufblk *bufBlk = NULL;

                UTLT_Assert(xact->step == 2 || xact->step == 3, return STATUS_ERROR,
                    "XactUpRx: XID: %d O: %s invalid S: %d for T: %d P: %s:%d",
                    xact->transactionId, 
                    xact->origin == PFCP_LOCAL_ORIGINATOR ? "local " : "remote", 
                    xact->step, type,
                    GetIP(&xact->gnode->sock->remoteAddr),
                    GetPort(&xact->gnode->sock->remoteAddr));

                bufBlk = xact->seq[2].bufBlk;
                if (bufBlk) {
                    UTLT_Warning("XactUpRx: Request Duplicated. Retransmit! XID: %d O: %s for T: %d P: %s:%d",
                        xact->transactionId, 
                        xact->origin == PFCP_LOCAL_ORIGINATOR ? "local" : "remote", xact->step, type,
                        GetIP(&xact->gnode->sock->remoteAddr),
                        GetPort(&xact->gnode->sock->remoteAddr));
                    status = PfcpSend(xact->gnode, bufBlk);
                    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "XactUpRx: PfcpSend error in local");
                } else {
                    UTLT_Warning("XactUpRx: Request Duplicated. Discard! XID: %d O: %s for T: %d P: %s:%d",
                        xact->transactionId, xact->origin == PFCP_LOCAL_ORIGINATOR ?
                        "local" : "remote", xact->step, type,
                        GetIP(&xact->gnode->sock->remoteAddr),
                        GetPort(&xact->gnode->sock->remoteAddr));
                }

                return STATUS_EAGAIN;
            }

            UTLT_Assert(xact->step == 1, return STATUS_ERROR,
                "XactUpRx: XID: %d O: %s invalid S: %d for T: %d P: %s:%d",
                xact->transactionId, 
                xact->origin == PFCP_LOCAL_ORIGINATOR ? "local" : "remote", 
                xact->step, type,
                GetIP(&xact->gnode->sock->remoteAddr),
                GetPort(&xact->gnode->sock->remoteAddr));
            break;
        case PFCP_XACT_FINAL_STAGE:
            UTLT_Assert(xact->step == 1, return STATUS_ERROR,
                "XactUpRx: XID: %d O: %s invalid S: %d for T: %d P: %s:%d",
                xact->transactionId, 
                xact->origin == PFCP_LOCAL_ORIGINATOR ? "local " : "remote", 
                xact->step, type,
                GetIP(&xact->gnode->sock->remoteAddr),
                GetPort(&xact->gnode->sock->remoteAddr));
            break;
        default:
            UTLT_Assert(0, return STATUS_ERROR, "XactUpRx: XID: %d invalid S: %d in local",
                xact->transactionId, xact->step);
        }
    } else if (xact->origin == PFCP_REMOTE_ORIGINATOR) {
        switch (stage) {
        case PFCP_XACT_INITIAL_STAGE:
            if (xact->seq[0].type == type) {
                Bufblk *bufBlk = NULL;

                UTLT_Assert(xact->step == 1 || xact->step == 2, return STATUS_ERROR,
                    "XactUpRx: XID: %d O: %s invalid SL %d for T: %d P: %s:%d",
                    xact->transactionId, 
                    xact->origin == PFCP_LOCAL_ORIGINATOR ? "local" : "remote", xact->step, type,
                    GetIP(&xact->gnode->sock->remoteAddr),
                    GetPort(&xact->gnode->sock->remoteAddr));

                bufBlk = xact->seq[1].bufBlk;
                if (bufBlk) {
                    UTLT_Warning("XactUpRx: Request Duplicated. Retransmit! XID: %d O: %s for S: %d T: %d P: %s:%d",
                        xact->transactionId, 
                        xact->origin == PFCP_LOCAL_ORIGINATOR ? "local" : "remote", 
                        xact->step, type, GetIP(&xact->gnode->sock->remoteAddr),
                        GetPort(&xact->gnode->sock->remoteAddr));
                    status = PfcpSend(xact->gnode, bufBlk);
                    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "XactUpRx: PfcpSend error in remote");
                } else {
                    UTLT_Warning("XactUpRx: Request Duplicated. Discard!  XID: %d O: %s for S: %d T: %d P: %s:%d",
                        xact->transactionId, 
                        xact->origin == PFCP_LOCAL_ORIGINATOR ? "local" : "remote", 
                        xact->step, type,
                        GetIP(&xact->gnode->sock->remoteAddr),
                        GetPort(&xact->gnode->sock->remoteAddr));
                }
                return STATUS_EAGAIN;
            }

            UTLT_Assert(xact->step == 0, return STATUS_ERROR,
                "XactUpRx: XID: %d O: %s invalid S: %d for T: %d P: %s:%d",
                xact->transactionId, 
                xact->origin == PFCP_LOCAL_ORIGINATOR ? "local" : "remote", 
                xact->step, type,
                GetIP(&xact->gnode->sock->remoteAddr),
                GetPort(&xact->gnode->sock->remoteAddr));
            break;

        case PFCP_XACT_INTERMEDIATE_STAGE:
            UTLT_Assert(0, return STATUS_ERROR, "XactUpRx: XID: %d invalid S: %d in remote", 
                xact->transactionId, xact->step);
            break;

        case PFCP_XACT_FINAL_STAGE:
            UTLT_Assert(xact->step == 2, return STATUS_ERROR,
                "XactUpRx: XID: %d O: %s invalid S: %d for T: %d P: %s:%d",
                xact->transactionId, 
                xact->origin == PFCP_LOCAL_ORIGINATOR ? "local" : "remote", 
                xact->step, type,
                GetIP(&xact->gnode->sock->remoteAddr),
                GetPort(&xact->gnode->sock->remoteAddr));
            break;

        default:
            UTLT_Assert(0, return STATUS_ERROR, "XactUpRx: XID: %d invalid S: %d in remote", 
                xact->transactionId, xact->step);
        }
    } else {
        UTLT_Assert(0, return STATUS_ERROR, "XactUpRx: XID: %d unknown O: %d",
            xact->transactionId, xact->origin);
    }

    xact->seq[xact->step].type = type;
    xact->step++;

    return STATUS_OK;
}

Status PfcpXactCommit(PfcpXact *xact) {
    Status status;
    uint8_t type;
    Bufblk *bufBlk = NULL;
    PfcpXactStage stage;

    UTLT_Assert(xact, return STATUS_ERROR, "XactCmt: xact NULL");
    UTLT_Assert(xact->gnode, return STATUS_ERROR, "XactCmt: node NULL");

    // Reference to Tx (Response)
    type = xact->seq[xact->step - 1].type;
    stage = PfcpXactGetStage(type, xact->transactionId);

    UTLT_Trace("XactCmt: Commit XID: %d O: %s T: %d S: %d P: %s:%d\n", 
        xact->transactionId,
        xact->origin == PFCP_LOCAL_ORIGINATOR ? "local" : "remote",
        type, stage,
        GetIP(&xact->gnode->sock->remoteAddr), 
        GetPort(&xact->gnode->sock->remoteAddr));

    if (xact->origin == PFCP_LOCAL_ORIGINATOR) {
        switch (stage) {
        case PFCP_XACT_INITIAL_STAGE:
            UTLT_Assert(xact->step == 1, return STATUS_ERROR,
                "XactCmt: XID: %d O: %s invalid S: %d for T: %d P: %s:%d",
                xact->transactionId, 
                xact->origin == PFCP_LOCAL_ORIGINATOR ? "local" : "remote", 
                xact->step, type,
                GetIP(&xact->gnode->sock->remoteAddr),
                GetPort(&xact->gnode->sock->remoteAddr));
            break;

        case PFCP_XACT_INTERMEDIATE_STAGE:
            UTLT_Assert(0, return STATUS_ERROR, "XactCmt: XID: %d invalid S: %d in local", 
                xact->transactionId, xact->step);

        case PFCP_XACT_FINAL_STAGE:
            UTLT_Assert(xact->step == 2 || xact->step == 3, return STATUS_ERROR,
                "XactCmt: XID: %d O: %s invalid S: %d for T: %d P: %s:%d",
                xact->transactionId, 
                xact->origin == PFCP_LOCAL_ORIGINATOR ? "local" : "remote", 
                xact->step, type,
                GetIP(&xact->gnode->sock->remoteAddr),
                GetPort(&xact->gnode->sock->remoteAddr));

            if (xact->step == 2) {
                UTLT_Debug("XactCmt: Local XID: %d Deleted type: %d",  
                    xact->transactionId, type);
                PfcpXactDelete(xact);
                return STATUS_OK;
            }
            break;

        default:
            UTLT_Assert(0, return STATUS_ERROR, "XactCmt: XID: %d invalid S: %d", 
                xact->transactionId, xact->step);
        }
    } else if (xact->origin == PFCP_REMOTE_ORIGINATOR) {
        switch (stage) {
        case PFCP_XACT_INITIAL_STAGE:
            UTLT_Assert(0, return STATUS_ERROR, "XactCmt: XID: %d invalid S: %d in remote", 
                xact->transactionId, xact->step);

        case PFCP_XACT_INTERMEDIATE_STAGE: {
            UTLT_Assert(xact->step == 2, return STATUS_ERROR,
                "XactCmt: XID: %d O: %s invalid S: %d for T: %d P: %s:%d",
                xact->transactionId,
                xact->origin == PFCP_LOCAL_ORIGINATOR ? "local" : "remote", 
                xact->step, type,
                GetIP(&xact->gnode->sock->remoteAddr),
                GetPort(&xact->gnode->sock->remoteAddr));
            break;
        }
        case PFCP_XACT_FINAL_STAGE: {
            UTLT_Assert(xact->step == 2 || xact->step == 3, return STATUS_ERROR,
                "XactCmt: XID: %d O: %s invalid S: %d for T: %d P: %s:%d",
                xact->transactionId,
                xact->origin == PFCP_LOCAL_ORIGINATOR ? "local" : "remote", 
                xact->step, type,
                GetIP(&xact->gnode->sock->remoteAddr),
                GetPort(&xact->gnode->sock->remoteAddr));

            if (xact->step == 3) {
                UTLT_Info("XactCmt: Remote XID: %d Deleted type: %d", 
                    xact->transactionId, type); 
                PfcpXactDelete(xact);
                return STATUS_OK;
            }
            break;
        }
        default:
            UTLT_Assert(0, return STATUS_ERROR, "XactCmt: XID: %d invalid S: %d in remote", 
                xact->transactionId, xact->step);
        }
    } else {
        UTLT_Assert(0, return STATUS_ERROR, "XactCmt: XID: %d unknown O: %d in remote", 
            xact->transactionId, xact->origin);
    }

    bufBlk = xact->seq[xact->step - 1].bufBlk;
    UTLT_Assert(bufBlk, return STATUS_ERROR, "XactCmt: XID: %d buffer NULL for T: %d",
         xact->transactionId, type);

    status = PfcpSend(xact->gnode, bufBlk);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, 
        "XactCmt: PfcpSend error XID: %d T: %d",
        xact->transactionId, type);

    UTLT_Debug("XactCmt: pfcp send response XID: %d T: %d", 
        xact->transactionId, type);
    return STATUS_OK;
}

Status PfcpXactTimeout(uint32_t index, uint32_t event, uint8_t *type) {
    PfcpXact *xact = NULL;
    xact = IndexFind(&pfcpXactPool, index);

    UTLT_Trace("XactTimeout: index %d and event %d", index, event);

    UTLT_Assert(xact, goto out, "XactTimeout: failed to find Xact XID: %d", index);
    UTLT_Assert(xact->gnode, goto out_del, "XactTimeout: XID: %d reference to NULL PfcpNode",
        xact->transactionId);
   
    if (type)
        *type = xact->seq[xact->step - 1].type;


    UTLT_Trace("XactTimeout: XID: %d O: %s S: %d T: %d P: %s:%d\n",
        xact->transactionId, 
        xact->origin == PFCP_LOCAL_ORIGINATOR ? "local" : "remote", 
        xact->step, xact->seq[xact->step - 1].type,
        GetIP(&xact->gnode->sock->remoteAddr),
        GetPort(&xact->gnode->sock->remoteAddr));

out_del:
    PfcpXactDelete(xact);
out:
    return STATUS_ERROR;
}

Status PfcpXactReceive(PfcpNode *gnode, PfcpHeader *header, PfcpXact **xact) {
    Status status;
    PfcpXact *newXact = NULL;

    UTLT_Assert(gnode, return STATUS_ERROR, "XactRcv: node NULL");
    UTLT_Assert(header, return STATUS_ERROR, "XactRcv: header NULL");

    // First find the given sequence number of request is in outstanding list
    // or not
    newXact = PfcpXactFindByTransactionId(gnode, 
        header->type,
        PfcpSqn2TransactionId(header->sqn));
    if (!newXact) {
        newXact = PfcpXactRemoteCreate(gnode, header->sqn);
    }
    UTLT_Assert(newXact, return STATUS_ERROR, "XactRcv: failed to create/find a new Xact");

    UTLT_Trace("XactRcv: XID: %d O: %s P: %s:%d\n",
        newXact->transactionId, 
        newXact->origin == PFCP_LOCAL_ORIGINATOR ? "local" : "remote",
        GetIP(&gnode->sock->remoteAddr), 
        GetPort(&gnode->sock->remoteAddr));

    status = PfcpXactUpdateRx(newXact, header->type);
    if (status != STATUS_OK) {
        UTLT_Error("XactRcv: Failed update Xact receive XID: %d T: %d", 
            newXact->transactionId, header->type);
        PfcpXactDelete(newXact);
        return status;
    }

    *xact = newXact;
    return STATUS_OK;
}

PfcpXact *PfcpXactFind(uint32_t index) {
    UTLT_Assert(index, return NULL, "XactFind: Invalid Index");
    return IndexFind(&pfcpXactPool, index);
}

PfcpXact *PfcpXactFindByTransactionId(PfcpNode *gnode, uint8_t type, uint32_t transactionId) {
    PfcpXact *xact = NULL;
    PfcpXact *nextNode = NULL;
    ListHead *list = NULL; 
    UTLT_Assert(gnode, return NULL, "FindXactId: node NULL");

    switch (PfcpXactGetStage(type, transactionId)) {
        case PFCP_XACT_INITIAL_STAGE:
            list = &gnode->remoteXactList;
            xact = ListFirst(&gnode->remoteXactList);
            break;
        case PFCP_XACT_INTERMEDIATE_STAGE:
            list = &gnode->localList;
            xact = ListFirst(&gnode->localList);
            break;
        case PFCP_XACT_FINAL_STAGE:
            if (transactionId & PFCP_MAX_XACT_ID) {
                list = &gnode->remoteXactList;
                xact = ListFirst(&gnode->remoteXactList);
            } else {
                list = &gnode->localList;
                xact = ListFirst(&gnode->localList);
            }                
            break;
        default:
            UTLT_Assert(0, return NULL, "FindXactId: Unknown stage");
    }
    
    ListForEachSafe(xact, nextNode, list) {
        if (xact->transactionId == transactionId)
            break;
    }

    if (xact == (PfcpXact *) list) {
        return NULL;
    }

    if (xact) {
        UTLT_Info("FindXactId: [%d] %s Find peer [%s]:%d\n",
            xact->transactionId, 
            xact->origin == PFCP_LOCAL_ORIGINATOR ? "local" : "remote",
            GetIP(&gnode->sock->remoteAddr), GetPort(&gnode->sock->remoteAddr));
    }

    return xact;
}

void PfcpXactAssociate(PfcpXact *xact1, PfcpXact *xact2) {
    UTLT_Assert(xact1, return, "XactAss: xact1 NULL");
    UTLT_Assert(xact2, return, "XactAss: xact2 NULL");

    UTLT_Assert(xact1->associatedXact == NULL, return, "XactAss: 1 Already assocaited");
    UTLT_Assert(xact2->associatedXact == NULL, return, "XactAss: 2 Already assocaited");

    xact1->associatedXact = xact2;
    xact2->associatedXact = xact1;

    return;
}
