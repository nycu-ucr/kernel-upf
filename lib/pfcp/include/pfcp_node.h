#ifndef __PFCP_NODE_H__
#define __PFCP_NODE_H__

#include "utlt_list.h"
#include "utlt_network.h"
#include "utlt_timer.h"

#include "pfcp_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _PfcpNode {
    ListHead        node;           /* List of node for PFCP */
    SockAddr        *saList;        /* Socket Address list */
    Sock            *sock;
    Ip              ip;

    ListHead        localList;
    ListHead        remoteXactList;

    uint8_t         state;            /* Association complete or not */
#define PFCP_NODE_ST_NULL           0
#define PFCP_NODE_ST_ASSOCIATED     1  

    TimerBlkID      timeHeartbeat;    /* no timer lib */
    PfcpNodeId      nodeId;
    
    union {
        uint8_t     upFunctionFeatures;
        uint8_t     cpFunctionFeatures;
    };
    PfcpUserPlaneIpResourceInformation  userPlaneInfo;
} PfcpNode;

Status PfcpNodeInit();
Status PfcpNodeTerminate();
PfcpNode * PfcpAddNodeWithSock(ListHead *list, SockAddr *from);
Status PfcpRemoveNode(ListHead *list, PfcpNode *node);
Status PfcpRemoveAllNodes(ListHead *list);
PfcpNode *PfcpFindNode(ListHead *list, PfcpFSeid *fSeid);
PfcpNode *PfcpFindNodeSockAddr(ListHead *list, SockAddr *sock);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PFCP_NODE_H__ */
