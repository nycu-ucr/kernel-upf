#ifndef __UPF_CONTEXT_H__
#define __UPF_CONTEXT_H__

#include <stdint.h>
#include <netinet/in.h>
#include <net/if.h>
#include <pthread.h>

#include "utlt_list.h"
#include "utlt_buff.h"
#include "utlt_event.h"
#include "utlt_thread.h"
#include "utlt_network.h"
#include "utlt_hash.h"
#include "utlt_3gppTypes.h"
#include "utlt_timer.h"

#include "pfcp_node.h"
#include "pfcp_message.h"

#include "up/up_match.h"

#include "updk/env.h"
#include "updk/init.h"
#include "updk/rule_pdr.h"
#include "updk/rule_far.h"
#include "updk/rule_qer.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define MAX_NUM_PACKET 500

typedef struct _UpfUeIp      UpfUeIp;
typedef struct _UpfDev       UpfDev;
typedef struct gtp5g_pdr     UpfPdr;
typedef struct gtp5g_far     UpfFar;
typedef struct _UpfBufPacket UpfBufPacket;

// Rule structure dependent on UPDK
typedef UPDK_PDR UpfPDR;
typedef UPDK_FAR UpfFAR;
typedef UPDK_QER UpfQER;
/*
typedef UPDK_BAR UpfBAR;
typedef UPDK_URR UpfURR;
*/

typedef enum _UpfEvent {

    UPF_EVENT_N4_MESSAGE,
    UPF_EVENT_SESSION_REPORT,
    UPF_EVENT_N4_T3_RESPONSE,
    UPF_EVENT_N4_T3_HOLDING,

    UPF_EVENT_TOP,

} UpfEvent;

typedef struct {
    uint8_t         role;                // UpfRole
    const char      *gtpDevNamePrefix;   // Default : "upfgtp"

    ListHead        gtpInterfaceList;    // name of interface (char*)
    // Add context related to GTP-U here
    uint16_t        gtpv1Port;           // Default : GTP_V1_PORT
    EnvParams       *envParams;          // EnvParams parsing from UPF Config
    Sock            upSock;              // User Plane Socket builds from Gtpv1EnvInit()

    // Add context related to PFCP here
    uint16_t        pfcpPort;            // Default : PFCP_PORT
    ListHead        pfcpIPList;          // PFCP IPv4 Server List (SockNode)
    ListHead        pfcpIPv6List;        // PFCP IPv6 Server List (SockNode)
    char            pfcpNodeIdAddr[256]; // PFCP Node ID Address (FQDN / IP)
    PfcpNodeId      pfcpNodeId;          // PFCP Node ID
    Sock            *pfcpSock;           // IPv4 Socket
    Sock            *pfcpSock6;          // IPv6 Socket
    SockAddr        *pfcpAddr;           // IPv4 Address
    SockAddr        *pfcpAddr6;          // IPv6 Address

    /* Use Array or Hash for better performance
     * Because max size of the list is 65536 due to the max of PDR ID
     * We can use array for O(1) search instead of O(N) search in list
     * Trade off of speed and memory size
     */
    //ListNode        bufPacketList;       // save pdrId and buffer here

    // DNS
#define MAX_NUM_OF_DNS          2
    const char      *dns[MAX_NUM_OF_DNS];
    const char      *dns6[MAX_NUM_OF_DNS];

    // Add other context here
    ListHead        ranS1uList;         // RAN List connected to UPF
    ListHead        upfN4List;          // UPF PFCP Node List
    ListHead        dnnList;

    // Different list of policy rule
    // TODO: if implementing QER in kernel, remove these list
    ListHead        qerList;
    ListHead        urrList;

    uint32_t        recoveryTime;       // UTC time
    TimerList       timerServiceList;

    // Add some self library structure here
    int             epfd;               // Epoll fd
    EvtQId          eventQ;             // Event queue communicate between UP and CP
    ThreadID        pktRecvThread;      // Receive packet thread

#define UPF_SEID_START  (1)
    uint64_t        nextSeid;           // unique to UPF, ++ on session create
    // Session : hash(IPv4 + SEID)
    Hash            *sessionHash;
    // Save buffer packet here
    Hash            *bufPacketHash;
    // Use spin lock to protect data write
    pthread_spinlock_t buffLock;
    // TODO: read from config
    // no reason, just want to bigger than /tmp/free5gc_unix_sock
#define MAX_SOCK_PATH_LEN 64
    char            buffSockPath[MAX_SOCK_PATH_LEN];
    // Buffering socket for recv packet from kernel
    Sock            *buffSock;


    // Config file
    const char      *configFilePath;
} UpfContext;

typedef struct _UpfUeIp {
    union {
        struct in_addr addr4;
        struct in6_addr addr6;
    };
} UpfUeIp;

typedef struct _SessionReqState {
    uint16_t        state;
#define SMF_UPF_SESSION_STATE_INIT      0x0000
#define SMF_UPF_SESSION_STATE_HANDLE    0x0001
#define SMF_UPF_SESSION_STATE_SEND_RSP  0x0002
#define SMF_UPF_SESSION_STATE_DELETED   0x0004
#define SMF_UPF_SESSION_STATE_RELEASE   0x0008
#define SMF_UPF_SESSION_STATE_ERROR     0xFFFF

    uint16_t        subState;
#define SMF_UPF_SESSION_SUB_STATE_INIT                  0x0000
#define SMF_UPF_SESSION_SUB_STATE_HANDLE_SUCCESS        0x1000
#define SMF_UPF_SESSION_SUB_STATE_HANDLE_FAILURE        0x1001
#define SMF_UPF_SESSION_SUB_STATE_HANDLE_RESCHEDULE     0x1002
#define SMF_UPF_SESSION_SUB_STATE_SEND_RSP_SUCCESS      0x2000
#define SMF_UPF_SESSION_SUB_STATE_SEND_RSP_FAILURE      0x2001
#define SMF_UPF_SESSION_SUB_STATE_SEND_RSP_RESCHDULE    0x2002
#define SMF_UPF_SESSION_SUB_STATE_DELETED_SUCCESS       0x4000
#define SMF_UPF_SESSION_SUB_STATE_DELETED_FAILURE       0x4001
#define SMF_UPF_SESSION_SUB_STATE_DELETED_RESCHDULE     0x4002

    uint32_t        sqn;
} SessionReqState;


#define PFCP_MAX_REQ_STATE                          3
#define ConvertReqTypeToStateIndex(type, index)     \
    do {                                            \
        ((index) = (((type) - 50) / 2));              \
    } while(0)

typedef struct _UpfSession {
    int             index;

    SessionReqState reqState[PFCP_MAX_REQ_STATE];

    // F-SEID 
    uint64_t        smfSeid;
    PfcpFSeid       smfFseid;

    uint64_t        upfSeid;
   
    /* Hashed key: hash(IPV4(4) + SEID(8)) 
    * TODO: IPv6 */
#define UPF_SESS_HASHKEY_SZ (16)
#define UPF_SESS_HASHKEY_SZ_HALF (8)
    uint8_t         hashKey[UPF_SESS_HASHKEY_SZ];
    int             hashKeylen;
    uint8_t         hashKeyR[UPF_SESS_HASHKEY_SZ]; /* hashkey with remote data  */
    int             hashKeylenR;                   /* hashkeylen of remote data */

    PfcpNode        *pfcpNode;

    ListHead        pdrIdList;
    ListHead        pdrList;
    ListHead        farList;
    ListHead        qerList;
    ListHead        barList;
    ListHead        urrList;

    /* PFCP Session Report Request(SRR) Outstanding list */
    ListHead        srrList;
} UpfSession;

typedef struct _UpfSRRNode {
    ListHead    node;

    UpfSession  *sess;
    uint16_t    pdrId;
    uint64_t    seid;

    uint8_t     state;
#define SRR_STATE_INIT      0x00
#define SRR_STATE_SENT      0x01
#define SRR_STATE_RECV      0x02
#define SRR_STATE_TIMER     0x04
#define SRR_STATE_TIMEOUT   0x08
#define SRR_STATE_RELEASE   0xFF

    uint16_t    seqCount;
#define SRR_MAX_SEQ_COUNT   0x20
    uint32_t    seqId[SRR_MAX_SEQ_COUNT];

    uint8_t     timerCount;
#define SRR_MAX_TIMEOUT_COUNT 0x03
    timer_t     timer;
} UpfSRRNode;

// Used for buffering, Index type for each PDR
typedef struct _UpfBufPacket {
    //ListHead        node;
    int             index;

    // If sessionPtr == NULL, this PDR don't exist
    // TS 29.244 5.2.1 shows that PDR won't cross session
    const UpfSession *sessionPtr;
    uint16_t        pdrId;
    Bufblk          *packetBuffer[MAX_NUM_PACKET];
    unsigned int used_buffer_length;
} UpfBufPakcet;

typedef struct {
    ListHead node;
    int index;

    UpfPDR pdr;

    MatchRuleNode *matchRule;
} UpfPDRNode;

typedef struct {
    ListHead node;
    int index;

    UpfFAR far;
} UpfFARNode;

typedef struct {
    ListHead node;
    int index;

    UpfQER qer;
} UpfQERNode;

typedef struct {
    ListHead node;
    int index;

    // UpfBAR bar;
} UpfBARNode;

typedef struct {
    ListHead node;
    int index;

    // UpfURR urr;
} UpfURRNode;

UpfContext *Self();
Status UpfContextInit();
Status UpfContextTerminate();

// Rules
UpfPDRNode *UpfPDRNodeAlloc();
UpfFARNode *UpfFARNodeAlloc();
UpfQERNode *UpfQERNodeAlloc();
UpfBARNode *UpfBARNodeAlloc();
UpfURRNode *UpfURRNodeAlloc();

void UpfPDRNodeFree(UpfPDRNode *node);
void UpfFARNodeFree(UpfFARNode *node);
void UpfQERNodeFree(UpfQERNode *node);
void UpfBARNodeFree(UpfBARNode *node);
void UpfURRNodeFree(UpfURRNode *node);

int UpfPDRFindByID(uint16_t id, void *ruleBuf);
int UpfFARFindByID(uint32_t id, void *ruleBuf);
int UpfQERFindByID(uint32_t id, void *ruleBuf);
/*
int UpfBARFindByID(uint32_t id, void *ruleBuf);
int UpfURRFindByID(uint32_t id, void *ruleBuf);
*/

Status HowToHandleThisPacket(uint32_t farID, uint8_t *action);

void UpfPDRDump();
void UpfFARDump();
void UpfQERDump();
/*
void UpfBARDump();
void UpfURRDump();
*/

UpfPDRNode *UpfPDRRegisterToSession(UpfSession *sess, UpfPDR *rule);
UpfFARNode *UpfFARRegisterToSession(UpfSession *sess, UpfFAR *rule);
UpfQERNode *UpfQERRegisterToSession(UpfSession *sess, UpfQER *rule);
/*
UpfBARNode *UpfBARRegisterToSession(UpfSession *sess, UpfBAR *rule);
UpfURRNode *UpfURRRegisterToSession(UpfSession *sess, UpfURR *rule);
*/

Status UpfPDRDeregisterToSessionByID(UpfSession *sess, uint16_t id);
Status UpfFARDeregisterToSessionByID(UpfSession *sess, uint32_t id);
Status UpfQERDeregisterToSessionByID(UpfSession *sess, uint32_t id);
/*
Status UpfBARDeregisterToSessionByID(UpfSession *sess, uint32_t id);
Status UpfURRDeregisterToSessionByID(UpfSession *sess, uint32_t id);
*/

// BufPacket
HashIndex *UpfBufPacketFirst();
HashIndex *UpfBufPacketNext(HashIndex *hashIdx);
UpfBufPacket *UpfBufPacketThis(HashIndex *hashIdx);
UpfBufPacket *UpfBufPacketFindByPdrId(uint16_t pdrId);
UpfBufPacket *UpfBufPacketAdd(const UpfSession * const session,
                              const uint16_t pdrId);
Status UpfBufPacketRemove(UpfBufPacket *bufPacket);
Status UpfBufPacketRemoveAll();

// Session
HashIndex *UpfSessionFirst();
HashIndex *UpfSessionNext(HashIndex *hashIdx);
UpfSession *UpfSessionThis(HashIndex *hashIdx);
UpfSession *UpfSessionAdd(PfcpFSeid *fseid);
Status UpfSessionRemove(UpfSession *session);
Status UpfSessionRemoveAll();
UpfSession *UpfSessionFindBySeid(uint64_t seid);
UpfSession *UpfSessionAddByMessage(PfcpMessage *message);
UpfSession *UpfSessionFindByPdrTeid(uint32_t teid);

UpfSRRNode * UpfSrrFindByPdrId(UpfSession *sess, uint16_t pdrId);
UpfSRRNode * UpfSrrFindBySeqId(UpfSession *sess, uint32_t seqId);
void UpfSrrRemoveAllNode(UpfSession *sess);
void UpfSrrAddNode(UpfSession *sess, UpfSRRNode *node);
void UpfSrrRemoveNode(UpfSRRNode *node);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UPF_CONTEXT_H__ */
