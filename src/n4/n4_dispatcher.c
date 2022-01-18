#define TRACE_MODULE _n4_dispatcher

#include <stdlib.h>

#include "utlt_debug.h"
#include "utlt_event.h"
#include "n4_pfcp_handler.h"
#include "pfcp_xact.h"
#include "pfcp_path.h"
#include "n4_pfcp_build.h"

#ifdef PFCP_REQUEST_DROP_TEST
static int sess_est_req_drop = 0;
#endif

void UpfDispatcher(const Event *event) {
    switch ((UpfEvent)event->type) {
    case UPF_EVENT_SESSION_REPORT: {
        Status status;
        PfcpHeader header;
        Bufblk *bufBlk = NULL;
        PfcpXact *xact = NULL;
        uint8_t srr_state = 0xFF;

        UpfSession *session = (UpfSession *) event->arg0;
        uint64_t seid = (uint64_t) event->arg1;
        uint16_t pdrId = (uint16_t) event->arg2;
        if (event->argc >= 4)
            srr_state = (uint8_t) event->arg3;

        UTLT_Assert(session != NULL, return,
                    "SESSION_REPORT: session is NULL");

        UpfSRRNode *srr = UpfSrrFindByPdrId(session, pdrId);
        if (srr != NULL && srr_state != SRR_STATE_TIMER) {
            UTLT_Info("SESSION_REPORT: exists an outstanding for PdrId: %u state: %u seqCnt: %u\n", 
                pdrId, srr->state, srr->seqCount);
            return;
        }

        memset(&header, 0, sizeof(PfcpHeader));
        header.type = PFCP_SESSION_REPORT_REQUEST;
        header.seid = seid;

        status = UpfN4BuildSessionReportRequestDownlinkDataReport(&bufBlk,
            header.type,
            session,
            pdrId);
        UTLT_Assert(status == STATUS_OK, return,
            "SESSION_REPORT: Build Session Report Request error");

        xact = PfcpXactLocalCreate(session->pfcpNode, &header, bufBlk);
        UTLT_Assert(xact, if (bufBlk) BufblkFree(bufBlk); return, 
            "SESSION_REPORT: pfcpXactLocalCreate error");

        /* UPF's PFCP Session Report Request can't be blocked, send a SRR to SMF 
         * iff memory allocation failed
         * */
        if (srr_state != SRR_STATE_TIMER) {
            srr = calloc(1, sizeof(*srr));
            if (srr) {
                srr->state = SRR_STATE_SENT;
                srr->sess = session;
                srr->pdrId = pdrId;
                srr->seid = seid;
                srr->seqCount = 1;
                srr->seqId[0] = header.sqn;
                UpfSrrAddNode(session, srr);
            }
        }

        status = PfcpXactCommit(xact);
        if (status != STATUS_OK) {
            UTLT_Error("SESSION_REPORT: xact commit error");

            /* TODO: Validate the return code and then decided what
             * should do?*/

            /* On failure, which means that we are not able to transmit 
             * a PFCP Session Report Request. The SRR Timer statemachine
             * will transmit an event to retry
             * */
            PfcpXactDelete(xact); 
        }

        /* On Success, Should not release the xaction because we will
         * get the same xact when SMF sends a response
         * 
         * TODO: Track the xaction information in SRR state machine
         * and release it when SRR max retry exceeds
         * */
        break;
    }
    case UPF_EVENT_N4_MESSAGE: {
        Status      status;
        Bufblk      *bufBlk = NULL;
        Bufblk      *recvBufBlk = (Bufblk *) event->arg0;
        SockAddr    *fromSock = (SockAddr *) event->arg1;
        PfcpNode    *pfcpN4Peer = NULL;
        PfcpMessage *pfcpMessage = NULL;
        PfcpXact    *xact = NULL;
        UpfSession  *session = NULL;

        UTLT_Assert(recvBufBlk, return, "N4_MESSAGE: Rcv buffer don't have data");
        UTLT_Assert(fromSock, return, "N4_MESSAGE: NULL fromSock");

        bufBlk = BufblkAlloc(1, sizeof(PfcpMessage));
        UTLT_Assert(bufBlk, goto freeRecvBuf, "N4_MESSAGE: Create buffer error");

        pfcpMessage = bufBlk->buf;
        UTLT_Assert(pfcpMessage, goto freeBuf, "N4_MESSAGE: PfcpMessage NULL");

        status = PfcpParseMessage(pfcpMessage, recvBufBlk);
        UTLT_Assert(status == STATUS_OK, goto freeBuf, "N4_MESSAGE: PfcpParseMessage error");

        if (pfcpMessage->header.seidP) {
            // Session Related message
            if (!pfcpMessage->header.seid) {
                if (pfcpMessage->header.type != PFCP_SESSION_ESTABLISHMENT_REQUEST) {
                    UTLT_Assert(0, goto freeBuf, "N4_MESSAGE: No SEID present and not a SessionEstReq");
                }
            }
            //FIXME: should find by both sip and sport and if Session Est., match it's nodeId
            //       currently, only find by sip.
            pfcpN4Peer = PfcpFindNodeSockAddr(&Self()->upfN4List, fromSock);
            UTLT_Assert(pfcpN4Peer, goto freeBuf, "N4_MESSAGE: session's pfcpN4Peer not found");

            if (pfcpMessage->header.type == PFCP_SESSION_ESTABLISHMENT_REQUEST) {
                session = UpfSessionAddByMessage(pfcpMessage);
            } else {
                session = UpfSessionFindBySeid(pfcpMessage->header.seid);
            }
          
            // TODO: If there is no session found and PFCP message type is Session Deletion 
            // Request then send success or proper message
            UTLT_Assert(session, goto freeBuf, "N4_MESSAGE: could not find session %#llx", 
                pfcpMessage->header.seid);

            if (pfcpMessage->header.type != PFCP_SESSION_REPORT_RESPONSE) {
                session->pfcpNode = pfcpN4Peer;
            }

            status = PfcpXactReceive(session->pfcpNode, &pfcpMessage->header, &xact);
            UTLT_Assert(status == STATUS_OK, goto freeBuf, "");

            /* To fill the session info into xact */
            PfcpXactStoreSession(xact, session);
        } else {
            // Node Related message
            if (pfcpMessage->header.type == PFCP_ASSOCIATION_SETUP_REQUEST) {
                /* Got Association Setup, this is only expected if there's
                   a new pfcpN4Peer. Handle in switch case below. */
                ;
            }
            else {
                pfcpN4Peer = PfcpFindNodeSockAddr(&Self()->upfN4List, fromSock);
                UTLT_Assert(pfcpN4Peer, goto freeBuf, "N4_MESSAGE: session's pfcpN4Peer not found");
                status = PfcpXactReceive(pfcpN4Peer, &pfcpMessage->header, &xact);
                UTLT_Assert(status == STATUS_OK, goto freeBuf, "");
            }
        }

        switch (pfcpMessage->header.type) {
        case PFCP_HEARTBEAT_REQUEST:
            UTLT_Debug("[PFCP] Handle PFCP heartbeat request");
            UpfN4HandleHeartbeatRequest(xact, 
                &pfcpMessage->heartbeatRequest);
            break;
        case PFCP_HEARTBEAT_RESPONSE:
            UTLT_Debug("[PFCP] Handle PFCP heartbeat response");
            UpfN4HandleHeartbeatResponse(xact, 
                &pfcpMessage->heartbeatResponse);
            break;
        case PFCP_ASSOCIATION_SETUP_REQUEST:
            UTLT_Debug("[PFCP] Handle PFCP association setup request");
            pfcpN4Peer = PfcpFindNodeSockAddr(&Self()->upfN4List, fromSock);
            /* FIXME: what if SMF just recovered from a crash ? */
            UTLT_Assert(NULL == pfcpN4Peer, goto freeBuf, "N4_MESSAGE: pfcpN4Peer already exists!?");

            pfcpN4Peer = PfcpAddNodeWithSock(&Self()->upfN4List, fromSock);
            UTLT_Assert(pfcpN4Peer, goto freeBuf, "N4_MESSAGE: pfcpN4Peer add node failed");
            pfcpN4Peer->sock = Self()->pfcpSock;

            status = PfcpXactReceive(pfcpN4Peer, &pfcpMessage->header, &xact);
            UTLT_Assert(status == STATUS_OK, goto freeBuf, "");

            UpfN4HandleAssociationSetupRequest(xact,
                &pfcpMessage->pFCPAssociationSetupRequest);
            break;
        case PFCP_ASSOCIATION_UPDATE_REQUEST:
            UTLT_Debug("[PFCP] Handle PFCP association update request");
            UpfN4HandleAssociationUpdateRequest(xact,
                &pfcpMessage->pFCPAssociationUpdateRequest);
            break;
        case PFCP_ASSOCIATION_RELEASE_RESPONSE:
            UTLT_Debug("[PFCP] Handle PFCP association release response");
            UpfN4HandleAssociationReleaseRequest(xact,
                &pfcpMessage->pFCPAssociationReleaseRequest);
            break;
        case PFCP_SESSION_ESTABLISHMENT_REQUEST:
            UTLT_Debug("[PFCP] Handle PFCP session establishment request");
#ifdef PFCP_REQUEST_DROP_TEST
            ++sess_est_req_drop;
            if ((sess_est_req_drop % PFCP_REQUEST_DROP_COUNT) == 0) {
                UTLT_Error("N4_MESSAGE: Dropped PFCP type: %u", pfcpMessage->header.type);
                break;
            }
#endif            
            UpfN4HandleSessionEstablishmentRequest(session, 
                xact,
                &pfcpMessage->header,
                &pfcpMessage->pFCPSessionEstablishmentRequest);
            //TODO: Release the previously allocated session resources
            break;
        case PFCP_SESSION_MODIFICATION_REQUEST:
            UTLT_Debug("[PFCP] Handle PFCP session modification request");
            UpfN4HandleSessionModificationRequest(session, 
                xact,
                &pfcpMessage->pFCPSessionModificationRequest);
            break;
        case PFCP_SESSION_DELETION_REQUEST:
            UTLT_Debug("[PFCP] Handle PFCP session deletion request");
            UpfN4HandleSessionDeletionRequest(session, 
                xact,
                &pfcpMessage->pFCPSessionDeletionRequest);
            break;
        case PFCP_SESSION_REPORT_RESPONSE:
            UTLT_Debug("[PFCP] Handle PFCP session report response");
            UpfN4HandleSessionReportResponse(session, 
                xact, 
                pfcpMessage->header.sqn,
                &pfcpMessage->pFCPSessionReportResponse);
            /* PFCP Session Report Request generated by local originator, and
             * got response. The response handler will free Xact.
             * */
            goto freeBuf;
        default:
            UTLT_Error("N4_MESSAGE: Unhandled PFCP type: %d", pfcpMessage->header.type);
        }
        PfcpXactDelete(xact); 
        freeBuf:
            PfcpStructFree(pfcpMessage);
            BufblkFree(bufBlk);
        freeRecvBuf:
            BufblkFree(recvBufBlk);
        break;
    }
    case UPF_EVENT_N4_T3_RESPONSE:
    case UPF_EVENT_N4_T3_HOLDING: {
        uint8_t type;
        PfcpXactTimeout((uint32_t) event->arg0, (UpfEvent)event->type, &type);
        UTLT_Error("Timeout event: %d xact.type: %d", (UpfEvent)event->type, type);
        break;
    }
    default: 
        UTLT_Error("No handler for event type: %d", event->type);
        break;
    }
}
