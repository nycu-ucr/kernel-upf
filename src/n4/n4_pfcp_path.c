#include "n4_pfcp_path.h"

#include <errno.h>
#include "utlt_event.h"
#include "utlt_buff.h"
#include "utlt_debug.h"
#include "n4_pfcp_handler.h"
#include "upf_context.h"
#include "pfcp_path.h"


/*
 * PFCP Packet Receiver
 */
static int _pfcpReceiveCB(Sock *sock, void *data) {
    //Event event;
    Status status;
    Bufblk *bufBlk = NULL;
    SockAddr from;
    PfcpHeader *pfcpHeader = NULL;

    UTLT_Assert(sock, return -1, "");

    status = PfcpReceiveFrom(sock, &bufBlk, &from);
    if (status != STATUS_OK) {
        if (errno == EAGAIN) {
            UTLT_Info("_pfcpReceiveCB: Failed to receive pfcp message(EAGAIN)");
            return 0;
        }
        UTLT_Info("_pfcpReceiveCB: Failed to receive pfcp message %d", status);
        return -1;
    }

    UTLT_Assert(from._family == AF_INET, return -1,
        "_pfcpReceiveCB: Support IPv4 only now");

    pfcpHeader = (PfcpHeader *)bufBlk->buf;
    if (pfcpHeader->version > PFCP_VERSION) {
        unsigned char vFail[8];
        PfcpHeader *pfcpOut = (PfcpHeader *)vFail;

        UTLT_Info("_pfcpReceiveCB: Unsupported PFCP version: %d", pfcpHeader->version);
        pfcpOut->flags = (PFCP_VERSION << 5);
        pfcpOut->type = PFCP_VERSION_NOT_SUPPORTED_RESPONSE;
        pfcpOut->length = htons(4);
        pfcpOut->sqn_only = pfcpHeader->sqn_only;
        // TODO: must check localAddress / remoteAddress / fd is correct?
        SockSendTo(sock, vFail, 8);
        BufblkFree(bufBlk);
        return STATUS_ERROR;
    }

    status = EventSend(Self()->eventQ, UPF_EVENT_N4_MESSAGE, 2, bufBlk, &from);
    if (status != STATUS_OK) {
        UTLT_Error("_pfcpReceiveCB: Failed to send an EventSend");
        BufblkFree(bufBlk);
        return STATUS_ERROR;
    }

    return 0;
}

Status PfcpServerInit() {
    Status status;

    status = PfcpServerList(&Self()->pfcpIPList, _pfcpReceiveCB, Self()->epfd);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "PfcpServerInit: Failed to start server");
                
    // TODO: IPv6 not support yet
    // status = PfcpServerList(&Self()->pfcpIPv6List, _pfcpReceiveCB, Self()->epfd);
    // UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
    //             "Create PFCP Server for IPv6 error");

    if (&Self()->pfcpIPList != NULL) {
        Self()->pfcpSock = PfcpLocalSockFirst(&Self()->pfcpIPList);
    }

    //if (&Self()->pfcpIPv6List != NULL) {
    //    Self()->pfcpSock6 = PfcpLocalSockFirst(&Self()->pfcpIPv6List);
    //}

    if (&Self()->pfcpIPList != NULL) {
        Self()->pfcpAddr = PfcpLocalAddrFirst(&Self()->pfcpIPList);
    }

    //if (&Self()->pfcpIPv6List != NULL) {
    //    Self()->pfcpAddr6 = PfcpLocalAddrFirst(&Self()->pfcpIPv6List);
    //}

    UTLT_Assert(Self()->pfcpAddr || Self()->pfcpAddr6, return STATUS_ERROR, 
        "PfcpServerInit: PFCP Server IP address is NULL");

    /* prepare the Node ID */
    if (strlen(Self()->pfcpNodeIdAddr) > 0) {
        char tmpaddr[sizeof(struct in6_addr)];
        PfcpNodeId *pNodeId = &Self()->pfcpNodeId;

        if (1 == inet_pton(AF_INET, Self()->pfcpNodeIdAddr, tmpaddr)) {
            pNodeId->spare = 0;
            pNodeId->type = PFCP_NODE_ID_IPV4;
            pNodeId->addr4.s_addr = ((struct in_addr *)&tmpaddr)->s_addr;
            Self()->pfcpAddr->s4.sin_addr.s_addr = pNodeId->addr4.s_addr;
            UTLT_Debug("IPV4 %s\n", Self()->pfcpNodeIdAddr);
        }
        else if (1 == inet_pton(AF_INET6, Self()->pfcpNodeIdAddr, tmpaddr)) {
            pNodeId->spare = 0;
            pNodeId->type = PFCP_NODE_ID_IPV6;
            memcpy(&pNodeId->addr6, tmpaddr, sizeof(pNodeId->addr6));
            memcpy(&Self()->pfcpAddr->s6.sin6_addr, tmpaddr, sizeof(pNodeId->addr6));
            UTLT_Debug("IPV6 %s\n", Self()->pfcpNodeIdAddr);
        }
        else {
            pNodeId->spare = 0;
            pNodeId->type = PFCP_NODE_ID_FQDN;
            FqdnEncode(pNodeId->fqdn, Self()->pfcpNodeIdAddr, sizeof(pNodeId->fqdn));
            UTLT_Debug("fqdn %s\n", Self()->pfcpNodeIdAddr);

            int result;
            char ip[INET6_ADDRSTRLEN];
            result = GetAddrFromHost(ip, Self()->pfcpNodeIdAddr, INET6_ADDRSTRLEN);
            if (result == STATUS_OK)
            {
                if (0 == inet_pton(AF_INET, ip, (void *)&Self()->pfcpAddr->s4.sin_addr))
                {
                    inet_pton(AF_INET6, ip, (void *)&Self()->pfcpAddr->s6.sin6_addr);
                }
            }
        }
    }

    return STATUS_OK;
}

Status PfcpServerTerminate() {
    SockListFree(&Self()->pfcpIPList);
    // SockListFree(&Self()->pfcpIPv6List);
    return STATUS_OK;
}
