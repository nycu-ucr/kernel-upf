#define TRACE_MODULE _upf_context

#include "upf_context.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <endian.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <netinet/in.h>
#include <net/if.h>

#include "utlt_debug.h"
#include "utlt_pool.h"
#include "utlt_index.h"
#include "utlt_hash.h"
#include "utlt_network.h"
#include "utlt_netheader.h"

#include "pfcp_message.h"
#include "pfcp_types.h"
#include "pfcp_xact.h"

#include "up/up_match.h"

#include "updk/env.h"
#include "updk/init.h"
#include "updk/rule.h"
#include "updk/rule_pdr.h"
#include "updk/rule_far.h"
#include "updk/rule_qer.h"

#include "upf_timer.h"

#define MAX_NUM_OF_SUBNET       16

IndexDeclare(upfSessionPool, UpfSession, MAX_POOL_OF_SESS);

#define MAX_NUM_OF_UPF_PDR_NODE     (MAX_POOL_OF_BEARER * 2)
#define MAX_NUM_OF_UPF_FAR_NODE     MAX_NUM_OF_UPF_PDR_NODE
#define MAX_NUM_OF_UPF_QER_NODE     (MAX_POOL_OF_SESS * 2)
#define MAX_NUM_OF_UPF_BAR_NODE     (MAX_POOL_OF_UE)
#define MAX_NUM_OF_UPF_URR_NODE     (MAX_POOL_OF_UE)

IndexDeclare(upfPDRNodePool, UpfPDRNode, MAX_NUM_OF_UPF_PDR_NODE);
IndexDeclare(upfFARNodePool, UpfFARNode, MAX_NUM_OF_UPF_FAR_NODE);
IndexDeclare(upfQERNodePool, UpfQERNode, MAX_NUM_OF_UPF_QER_NODE);
IndexDeclare(upfBARNodePool, UpfBARNode, MAX_NUM_OF_UPF_BAR_NODE);
IndexDeclare(upfURRNodePool, UpfURRNode, MAX_NUM_OF_UPF_URR_NODE);

/**
 * PDRHash - Store PDRs with Hash struct
 */
Hash *PDRHash;
pthread_mutex_t PDRHashLock;
Hash *FARHash;
pthread_mutex_t FARHashLock;
Hash *QERHash;
pthread_mutex_t QERHashLock;
Hash *BARHash;
pthread_mutex_t BARHashLock;
Hash *URRHash;
pthread_mutex_t URRHashLock;

#define Rule_Thread_Safe(__ruleType, expr) \
    pthread_mutex_lock(&__ruleType##HashLock); \
    expr; \
    pthread_mutex_unlock(&__ruleType##HashLock)

#define PDR_Thread_Safe(expr) Rule_Thread_Safe(PDR, expr)
#define FAR_Thread_Safe(expr) Rule_Thread_Safe(FAR, expr)
#define QER_Thread_Safe(expr) Rule_Thread_Safe(QER, expr)
#define BAR_Thread_Safe(expr) Rule_Thread_Safe(BAR, expr)
#define URR_Thread_Safe(expr) Rule_Thread_Safe(URR, expr)

static UpfContext self;
static _Bool upfContextInitialized = 0;

UpfContext *Self() {
    return &self;
}

#define RuleInit(__ruleType) do { \
    IndexInit(&upf##__ruleType##NodePool, MAX_NUM_OF_UPF_##__ruleType##_NODE); \
    __ruleType##Hash = HashMake(); \
    pthread_mutex_init(&__ruleType##HashLock, 0); \
} while (0)

Status UpfContextInit() {
    UTLT_Assert(upfContextInitialized == 0, return STATUS_ERROR,
                "UPF context has been initialized!");

    memset(&self, 0, sizeof(UpfContext));

    // TODO : Add GTPv1 init here
    self.envParams = AllocEnvParams();
    UTLT_Assert(self.envParams, return STATUS_ERROR,
        "EnvParams alloc failed");
    self.envParams->virtualDevice->eventCB.PacketInL3 = PacketInWithL3;
    self.envParams->virtualDevice->eventCB.PacketInGTPU = PacketInWithGTPU;
    self.envParams->virtualDevice->eventCB.getPDR = UpfPDRFindByID;
    self.envParams->virtualDevice->eventCB.getFAR = UpfFARFindByID;
    self.envParams->virtualDevice->eventCB.getQER = UpfQERFindByID;

    self.upSock.fd = -1;
    SockSetEpollMode(&self.upSock, EPOLLIN);


    // TODO : Add PFCP init here
    ListHeadInit(&self.pfcpIPList);
    // ListHeadInit(&self.pfcpIPv6List);
    self.nextSeid = UPF_SEID_START;

    // TODO : Add by self if context has been updated
    // TODO: check if gtp node need to init?
    // ListHeadInit(&self.pfcpIPList);
    // ListHeadInit(&self.pfcpIPv6List);

    ListHeadInit(&self.ranS1uList);
    ListHeadInit(&self.upfN4List);
    ListHeadInit(&self.dnnList);
    ListHeadInit(&self.qerList);
    ListHeadInit(&self.urrList);

    self.recoveryTime = htonl(time((time_t *)NULL));

    // Set Default Value
    self.gtpDevNamePrefix = "upfgtp";
    // defined in utlt_3gpptypes instead of GTP_V1_PORT defined in GTP_PATH;
    self.gtpv1Port = GTPV1_U_UDP_PORT;
    self.pfcpPort = PFCP_UDP_PORT;
    strcpy(self.envParams->virtualDevice->deviceID, self.gtpDevNamePrefix);

    // Init Resource
    IndexInit(&upfSessionPool, MAX_POOL_OF_SESS);
    RuleInit(PDR);
    RuleInit(FAR);
    RuleInit(QER);
    RuleInit(BAR);
    RuleInit(URR);
    MatchInit();

    PfcpNodeInit(); // init pfcp node for upfN4List (it will used pfcp node)
    TimerListInit(&self.timerServiceList);

    // TODO: Read from config
    strncpy(self.buffSockPath, "/tmp/free5gc_unix_sock", MAX_SOCK_PATH_LEN);
    self.sessionHash = HashMake();
    self.bufPacketHash = HashMake();
    // spin lock protect write data instead of mutex protect code block
    int ret = pthread_spin_init(&self.buffLock, PTHREAD_PROCESS_PRIVATE);
    UTLT_Assert(ret == 0, , "buffLock cannot create: %s", strerror(ret));

    upfContextInitialized = 1;

    return STATUS_OK;
}

#define RuleTerminate(__ruleType) do { \
    pthread_mutex_destroy(&__ruleType##HashLock); \
    IndexTerminate(&upf##__ruleType##NodePool); \
    HashDestroy(__ruleType##Hash); \
} while (0)

// TODO : Need to Remove List Members iterativelyatively
Status UpfContextTerminate() {
    UTLT_Assert(upfContextInitialized == 1, return STATUS_ERROR,
                "UPF context has been terminated!");

    Status status = STATUS_OK;

    int ret = pthread_spin_destroy(&self.buffLock);
    UTLT_Assert(ret == 0, , "buffLock cannot destroy: %s", strerror(ret));
    UTLT_Assert(self.bufPacketHash, , "Buffer Hash Table missing?!");
    HashDestroy(self.bufPacketHash);

    UTLT_Assert(self.sessionHash, , "Session Hash Table missing?!");
    HashDestroy(self.sessionHash);

    // Terminate resource
    MatchTerm();
    IndexTerminate(&upfSessionPool);
    RuleTerminate(PDR);
    RuleTerminate(FAR);
    RuleTerminate(QER);
    RuleTerminate(BAR);
    RuleTerminate(URR);

    PfcpRemoveAllNodes(&self.upfN4List);
    PfcpNodeTerminate();

    // TODO: remove gtpv1TunnelList, ranS1uList, upfN4LIst, dnnList,
    // pdrList, farList, qerList, urrLIist
    SockNodeListFree(&self.pfcpIPList);
    // SockNodeListFree(&self.pfcpIPv6List);
    FreeVirtualDevice(self.envParams->virtualDevice);

    UpfBufPacketRemoveAll();

    upfContextInitialized = 0;

    return status;
}

#define RuleNodeAlloc(__ruleType) \
Upf##__ruleType##Node *Upf##__ruleType##NodeAlloc() { \
    Upf##__ruleType##Node *node = NULL; \
    IndexAlloc(&upf##__ruleType##NodePool, node); \
    ListHeadInit(&node->node); \
    return node; \
}

RuleNodeAlloc(PDR);
RuleNodeAlloc(FAR);
RuleNodeAlloc(QER);
RuleNodeAlloc(BAR);
RuleNodeAlloc(URR);

#define RuleNodeFree(__ruleType) \
void Upf##__ruleType##NodeFree(Upf##__ruleType##Node *node) { \
    if (node) IndexFree(&upf##__ruleType##NodePool, node); \
}

RuleNodeFree(PDR);
RuleNodeFree(FAR);
RuleNodeFree(QER);
RuleNodeFree(BAR);
RuleNodeFree(URR);

#define UPF_RULE_ID(__ruleName) __ruleName ## Id

// Do the thread safe to upper layer function
#define RuleNodeHashSet(__ruleType, __id, __ptr) HashSet(__ruleType##Hash, &(__id), sizeof(__id), (__ptr))
#define RuleNodeHashGet(__ruleType, __id) HashGet(__ruleType##Hash, &(__id), sizeof(__id))

#define RuleFindByID(__ruleType, __ruleName, __keyType) \
int Upf##__ruleType##FindByID(__keyType id, void *ruleBuf) { \
    __ruleType##_Thread_Safe( \
        Upf##__ruleType##Node *node = RuleNodeHashGet(__ruleType, id); \
    ); \
    if (!node) return -1; \
    memcpy(ruleBuf, &node->__ruleName, sizeof(Upf##__ruleType)); \
    return 0; \
}

RuleFindByID(PDR, pdr, uint16_t);
RuleFindByID(FAR, far, uint32_t);
RuleFindByID(QER, qer, uint32_t);
/* TODO: Not support yet
RuleFindByID(BAR, bar, uint32_t);
RuleFindByID(URR, urr, uint32_t);
*/

Status HowToHandleThisPacket(uint32_t farID, uint8_t *action) {
    Status status = STATUS_OK;
    FAR_Thread_Safe(
        UpfFARNode *node = RuleNodeHashGet(FAR, farID);
        if (!node)
            status = STATUS_ERROR;
        else
            *action = node->far.applyAction;
    );
    return status;
}

#define RuleDump(__ruleType, __ruleName, __keyType) \
void Upf##__ruleType##Dump() { \
    __ruleType##_Thread_Safe( \
        for (HashIndex *hi = HashFirst(__ruleType ## Hash); hi; hi = HashNext(hi)) { \
            const __keyType *key = HashThisKey(hi); \
            UTLT_Info(#__ruleType" ID[%u] does exist", *key); \
        } \
     ); \
}

RuleDump(PDR, pdr, uint16_t);
RuleDump(FAR, far, uint32_t);
RuleDump(QER, qer, uint32_t);
/* TODO: Not support yet
RuleDump(BAR, bar, uint32_t);
RuleDump(URR, urr, uint32_t);
*/

UpfPDRNode *UpfPDRRegisterToSession(UpfSession *sess, UpfPDR *rule) {
    UTLT_Assert(sess && rule, return NULL, "Session or UpfPDR should not be NULL");
    UTLT_Assert(rule->flags.pdrId, return NULL, "PDR ID should be set");

    MatchRuleNode *newMatchRule = MatchRuleNodeAlloc();
    UTLT_Assert(newMatchRule, return NULL, "MatchRuleNodeAlloc failed");

    UTLT_Assert(MatchRuleCompile(rule, newMatchRule) == STATUS_OK, goto FREEMATCHRULENODE,
        "MatchRuleCompile failed");

    PDR_Thread_Safe(
        UpfPDRNode *ruleNode = RuleNodeHashGet(PDR, rule->pdrId);
        if (!ruleNode) {
            ruleNode = UpfPDRNodeAlloc();
            UTLT_Assert(ruleNode, goto FREEMATCHRULENODE, "UpfPDENodeAlloc failed");

            ListInsert(ruleNode, &sess->pdrList);
        } else {
            MatchRuleDeregister(ruleNode->matchRule);
            MatchRuleNodeFree(ruleNode->matchRule);
        }
        memcpy(&ruleNode->pdr, rule, sizeof(UpfPDR));
        ruleNode->matchRule = newMatchRule;
        newMatchRule->pdr = &ruleNode->pdr;
        RuleNodeHashSet(PDR, ruleNode->pdr.pdrId, ruleNode);
    );

    MatchRuleRegister(newMatchRule);

    return ruleNode;

FREEMATCHRULENODE:
    MatchRuleNodeFree(newMatchRule);

    return NULL;
}

#define RuleRegisterToSession(__ruleType, __ruleName) \
Upf##__ruleType##Node *Upf##__ruleType##RegisterToSession(UpfSession *sess, Upf##__ruleType *rule) { \
    UTLT_Assert(sess && rule, return NULL, "Session or Upf"#__ruleType" should not be NULL"); \
    UTLT_Assert(rule->flags.UPF_RULE_ID(__ruleName), return NULL, #__ruleType" ID should be set"); \
    __ruleType##_Thread_Safe( \
        Upf##__ruleType##Node *ruleNode = RuleNodeHashGet(__ruleType, rule->UPF_RULE_ID(__ruleName)); \
        if (!ruleNode) { \
            ruleNode = Upf##__ruleType##NodeAlloc(); \
            UTLT_Assert(ruleNode, return NULL, "Upf"#__ruleType"NodeAlloc failed"); \
            ListInsert(ruleNode, &sess->__ruleName##List); \
        } \
        memcpy(&ruleNode->__ruleName, rule, sizeof(Upf##__ruleType)); \
        RuleNodeHashSet(__ruleType, ruleNode->__ruleName.UPF_RULE_ID(__ruleName), ruleNode); \
    ); \
    return ruleNode; \
}

RuleRegisterToSession(FAR, far);
RuleRegisterToSession(QER, qer);
/* TODO: Not support yet
RuleRegisterToSession(BAR, bar);
RuleRegisterToSession(URR, urr);
*/

// Do the thread safe to upper layer function
#define RuleDeletionFromSession(__ruleType, __ruleName, __sessPtr, __nodePtr) do { \
    RuleNodeHashSet(__ruleType, (__nodePtr)->__ruleName.UPF_RULE_ID(__ruleName), NULL); \
    ListRemove(__nodePtr); \
} while (0)


static void UpfPDRDeregisterToSessionByNodeNoSafe(UpfSession *sess, UpfPDRNode *ruleNode) {
    if (ruleNode->matchRule) {
        MatchRuleDeregister(ruleNode->matchRule);
        MatchRuleNodeFree(ruleNode->matchRule);
    }

    RuleDeletionFromSession(PDR, pdr, sess, ruleNode);
    UpfPDRNodeFree(ruleNode);
}

static void UpfPDRDeregisterToSessionByNode(UpfSession *sess, UpfPDRNode *ruleNode) {
    PDR_Thread_Safe(
        UpfPDRDeregisterToSessionByNodeNoSafe(sess, ruleNode);
    );
}

Status UpfPDRDeregisterToSessionByID(UpfSession *sess, uint16_t id) {
    UTLT_Assert(sess, return STATUS_ERROR, "Session should not be NULL");

    PDR_Thread_Safe(
        UpfPDRNode *ruleNode = RuleNodeHashGet(PDR, id);
        UTLT_Assert(ruleNode, return STATUS_ERROR, "PDR ID[%u] does NOT exist", id);

        UpfPDRDeregisterToSessionByNodeNoSafe(sess, ruleNode);
    );

    return STATUS_OK;
}

#define RuleDeregisterToSessionByID(__ruleType, __ruleName, __keyType) \
Status Upf##__ruleType##DeregisterToSessionByID(UpfSession *sess, __keyType id) { \
    UTLT_Assert(sess, return STATUS_ERROR, "Session should not be NULL"); \
    __ruleType##_Thread_Safe( \
        Upf##__ruleType##Node *ruleNode = RuleNodeHashGet(__ruleType, id); \
        UTLT_Assert(ruleNode, return STATUS_ERROR, #__ruleType" ID[%u] does NOT exist", id); \
        RuleDeletionFromSession(__ruleType, __ruleName, sess, ruleNode); \
    ); \
    Upf##__ruleType##NodeFree(ruleNode); \
    return STATUS_OK; \
}

RuleDeregisterToSessionByID(FAR, far, uint32_t);
RuleDeregisterToSessionByID(QER, qer, uint32_t);
/* TODO: Not support yet
RuleDeregisterToSessionByID(BAR, bar, uint32_t);
RuleDeregisterToSessionByID(URR, urr, uint32_t);
*/

#define UPF_RULE_LIST(__ruleName) __ruleName ## List

void UpfPDRListDeletionAndFreeWithGTPv1Tunnel(UpfSession *sess) {
    UpfPDRNode *ruleNode;
    UpfPDRNode *nextNode;
    ruleNode = ListFirst(&(sess)->pdrList);
    while (ruleNode != (UpfPDRNode *) &(sess)->pdrList) {
        nextNode = (UpfPDRNode *) ListNext(ruleNode);
        UTLT_Assert(!Gtpv1TunnelRemovePDR(&ruleNode->pdr), ,
            "Remove PDR[%u] failed", ruleNode->pdr.pdrId);

        UpfPDRDeregisterToSessionByNode(sess, ruleNode);
        ruleNode = nextNode;
    }
}

// Do the thread safe to upper layer function
#define RuleListDeletionAndFreeWithGTPv1Tunnel(__ruleType, __ruleName) \
void Upf##__ruleType##ListDeletionAndFreeWithGTPv1Tunnel(UpfSession *sess) { \
    Upf##__ruleType##Node *ruleNode; \
    Upf##__ruleType##Node *nextNode; \
    ruleNode = ListFirst(&(sess)->UPF_RULE_LIST(__ruleName)); \
    while (ruleNode != (Upf##__ruleType##Node *) &(sess)->UPF_RULE_LIST(__ruleName)) { \
        nextNode = (Upf##__ruleType##Node *)ListNext(ruleNode); \
        UTLT_Assert(!Gtpv1TunnelRemove##__ruleType(&ruleNode->__ruleName), , \
            "Remove "#__ruleType"[%u] failed", ruleNode->__ruleName.UPF_RULE_ID(__ruleName)); \
        RuleDeletionFromSession(__ruleType, __ruleName, (sess), ruleNode); \
        IndexFree(&upf##__ruleType##NodePool, ruleNode); \
        ruleNode = nextNode; \
    }  \
}

RuleListDeletionAndFreeWithGTPv1Tunnel(FAR, far);
RuleListDeletionAndFreeWithGTPv1Tunnel(QER, qer);
/* TODO: Uncomment these if finish these implementation
RuleListDeletionAndFreeWithGTPv1Tunnel(URR, urr);
RuleListDeletionAndFreeWithGTPv1Tunnel(BAR, bar);
*/

HashIndex * UpfBufPacketFirst() {
    UTLT_Assert(self.bufPacketHash, return NULL, "");
    return HashFirst(self.bufPacketHash);
}

HashIndex * UpfBufPacketNext(HashIndex *hashIdx) {
    UTLT_Assert(hashIdx, return NULL, "");
    return HashNext(hashIdx);
}

UpfBufPacket * UpfBufPacketThis(HashIndex *hashIdx) {
    UTLT_Assert(hashIdx, return NULL, "");
    return (UpfBufPacket *)HashThisVal(hashIdx);
}

UpfBufPacket * UpfBufPacketFindByPdrId(uint16_t pdrId) {
    return (UpfBufPacket*)HashGet(self.bufPacketHash,
                                  &pdrId, sizeof(uint16_t));
}

UpfBufPacket * UpfBufPacketAdd(const UpfSession * const session,
                              const uint16_t pdrId) {
    UTLT_Assert(session, return NULL, "No session");
    UTLT_Assert(pdrId, return NULL, "PDR ID cannot be 0");

    UpfBufPacket *newBufPacket = UTLT_Malloc(sizeof(UpfBufPacket));
    UTLT_Assert(newBufPacket, return NULL, "Allocate new slot error");
    newBufPacket->sessionPtr = session;
    newBufPacket->pdrId = pdrId;
    newBufPacket->used_buffer_length = 0;
    int i;
    for(i = 0 ; i < MAX_NUM_PACKET ; i++){
        newBufPacket->packetBuffer[i] = NULL;
    }

    HashSet(self.bufPacketHash, &newBufPacket->pdrId,
            sizeof(uint16_t), newBufPacket);

    //ListAppend(&Self()->bufPacketList, newBufPacket);
    return newBufPacket;
}

Status UpfBufPacketRemove(UpfBufPacket *bufPacket) {
    UTLT_Assert(bufPacket, return STATUS_ERROR,
                "Input bufPacket error");
    Status status;

    bufPacket->sessionPtr = NULL;
    //bufPacket->pdrId = 0;
    //remove all buffer array
    int i;
    for(i = 0 ; i < MAX_NUM_PACKET ; i++){
        if (bufPacket->packetBuffer[i]) {
            status = BufblkFree(bufPacket->packetBuffer[i]);
            UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                        "packet in bufPacket free error");
        }
    }

    HashSet(self.bufPacketHash, &bufPacket->pdrId,
            sizeof(uint16_t), NULL);
    //ListRemove(&Self()->bufPacketList, bufPacket);
    status = UTLT_Free(bufPacket);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "bufPacket free error");

    return STATUS_OK;
}

Status UpfBufPacketRemoveAll() {
    HashIndex *hashIdx = NULL;
    UpfBufPacket *bufPacket = NULL;

    for (hashIdx = UpfBufPacketFirst(); hashIdx;
         hashIdx = UpfBufPacketNext(hashIdx)) {
        bufPacket = UpfBufPacketThis(hashIdx);
        UpfBufPacketRemove(bufPacket);
    }

    return STATUS_OK;
}

HashIndex * UpfSessionFirst() {
    UTLT_Assert(self.sessionHash, return NULL, "");
    return HashFirst(self.sessionHash);
}

HashIndex * UpfSessionNext(HashIndex *hashIdx) {
    UTLT_Assert(hashIdx, return NULL, "");
    return HashNext(hashIdx);
}

UpfSession * UpfSessionThis(HashIndex *hashIdx) {
    UTLT_Assert(hashIdx, return NULL, "");
    return (UpfSession *)HashThisVal(hashIdx);
}

/*
 * PFCP SEID assigned by UPF will be unique to all interacting SMFs.
 */
static void SessionHashKeygen(UpfSession *session, uint8_t *buf, uint8_t buflen) {
    int outlen = 0;
    outlen = (buflen > sizeof(session->hashKey)) ? sizeof(session->hashKey) : buflen;
    memcpy(session->hashKey, buf, outlen);
    session->hashKeylen = outlen;
    return;
}

static void SessionHashKeygenRemote(UpfSession *session, PfcpFSeid *fseidPeer) {
    memcpy(session->hashKeyR,                          &fseidPeer->seid,  UPF_SESS_HASHKEY_SZ_HALF);
    memcpy(session->hashKeyR+UPF_SESS_HASHKEY_SZ_HALF, &fseidPeer->addr4, UPF_SESS_HASHKEY_SZ_HALF);
    session->hashKeylenR = UPF_SESS_HASHKEY_SZ;
    return;
}

UpfSession * UpfSessionAdd(PfcpFSeid *fseidPeer) {
    UpfSession *session = NULL;

    UTLT_Assert(fseidPeer->v4, return NULL, "SessAdd: FSEID has no IPv4 flag(%#02x)", fseidPeer->v4);
    IndexAlloc(&upfSessionPool, session);
    UTLT_Assert(session, return NULL, "SessAdd: Failed to allocate session");

    memset(&session->reqState, 0, sizeof(session->reqState));

    ListHeadInit(&session->pdrIdList);
    ListHeadInit(&session->pdrList);
    ListHeadInit(&session->farList);
    ListHeadInit(&session->qerList);
    ListHeadInit(&session->barList);
    ListHeadInit(&session->urrList);

    /* Init PFCP Session Report Request list */
    ListHeadInit(&session->srrList);

    session->smfSeid = be64toh(fseidPeer->seid);
    memcpy((char*)&session->smfFseid, fseidPeer, sizeof(session->smfFseid));
    session->upfSeid = self.nextSeid++;

    SessionHashKeygen(session, (uint8_t *) &session->upfSeid, sizeof(session->upfSeid));
    SessionHashKeygenRemote(session, &session->smfFseid);

    HashSet(self.sessionHash, session->hashKey,  session->hashKeylen,  session);
    HashSet(self.sessionHash, session->hashKeyR, session->hashKeylenR, session);

    UTLT_Debug("SessAdded: SMF SEID: %#llx, UPF SEID: %#llx, addr4: %#08x HKeyL: %#x HCnt: %u",
        session->smfSeid, session->upfSeid, fseidPeer->addr4, 
        session->hashKeylen, self.sessionHash->count);
    UTLT_Debug("SessAdded: HKey: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
        session->hashKey[0], session->hashKey[1], session->hashKey[2], session->hashKey[3],
        session->hashKey[4], session->hashKey[5], session->hashKey[6], session->hashKey[7],
        session->hashKey[8], session->hashKey[9], session->hashKey[10], session->hashKey[11]);
   
    return session;
}

Status UpfSessionRemove(UpfSession *session) {
    UTLT_Assert(self.sessionHash, return STATUS_ERROR, "SessRem: session's hash NULL");
    UTLT_Assert(session, return STATUS_ERROR, "SessRem: session NULL");

    HashSet(self.sessionHash, session->hashKey,  session->hashKeylen,  NULL);
    HashSet(self.sessionHash, session->hashKeyR, session->hashKeylenR, NULL);

    // if (session->ueIpv4) {
    //     UpfUeIPFree(session->ueIpv4);
    // }
    // if (session->ueIpv6) {
    //     UpfUeIPFree(session->ueIpv6);
    // }

    uint16_t pdrId;
    UpfPDRNode *ruleNode, *nextNode;
    ruleNode = ListFirst(&(session)->pdrList);
    while (ruleNode != (UpfPDRNode *)&(session)->pdrList) {
        nextNode = (UpfPDRNode *)ListNext(ruleNode);
        pdrId = ruleNode->pdr.pdrId;
        UpfBufPacket *tmpBufPacket = UpfBufPacketFindByPdrId(pdrId);
        if (tmpBufPacket != NULL) {
            UpfBufPacketRemove(tmpBufPacket);
        }
        ruleNode = nextNode;
    }

    UpfFARListDeletionAndFreeWithGTPv1Tunnel(session);
    UpfQERListDeletionAndFreeWithGTPv1Tunnel(session);
    UpfPDRListDeletionAndFreeWithGTPv1Tunnel(session);

    /* TODO: Not support yet
    UpfBARListDeletionAndFreeWithGTPv1Tunnel(session);
    UpfURRListDeletionAndFreeWithGTPv1Tunnel(session);
    */
   
    UpfSrrRemoveAllNode(session);

    IndexFree(&upfSessionPool, session);
    
    return STATUS_OK;
}

Status UpfSessionRemoveAll() {
    HashIndex *hashIdx = NULL;
    UpfSession *session = NULL;

    for (hashIdx = UpfSessionFirst(); hashIdx;
         hashIdx = UpfSessionNext(hashIdx)) {
        session = UpfSessionThis(hashIdx);
        UpfSessionRemove(session);
    }

    return STATUS_OK;
}

UpfSession * UpfSessionFindBySeid(uint64_t seid) {
    uint8_t hashKey[UPF_SESS_HASHKEY_SZ];
    int hashKeylen = 0;
    UpfSession *session = NULL;

    UTLT_Assert(seid, return NULL, "SessFindSeid: SEID is ZERO");
    memcpy(hashKey, (char *)&seid, sizeof(seid));
    hashKeylen = sizeof(seid);

    UTLT_Debug("SessFindSeid: SEID: %#llx HCnt: %u", seid, self.sessionHash->count);
    UTLT_Debug("SessFindSeid: HKey: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
        hashKey[0], hashKey[1], hashKey[2], hashKey[3],
        hashKey[4], hashKey[5], hashKey[6], hashKey[7],
        hashKey[8], hashKey[9], hashKey[10], hashKey[11]);

    session = HashGet(self.sessionHash, hashKey, hashKeylen);
    return session;
}

UpfSession * UpfSessionFindByPeerFseid(PfcpFSeid *fseidPeer) {
    uint8_t hashKey[UPF_SESS_HASHKEY_SZ];
    int hashKeylen = 0;
    UpfSession *session = NULL;

    UTLT_Assert(fseidPeer, return NULL, "SessFindFseid: FSEID is NULL");
    memcpy(hashKey,                          &fseidPeer->seid,  UPF_SESS_HASHKEY_SZ_HALF);
    memcpy(hashKey+UPF_SESS_HASHKEY_SZ_HALF, &fseidPeer->addr4, UPF_SESS_HASHKEY_SZ_HALF);
    hashKeylen = 16;

    UTLT_Debug("SessFindFseid: fSEID->seid: %#llx HCnt: %u", fseidPeer->seid, self.sessionHash->count);
    UTLT_Debug("SessFindFseid: HKey: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
        hashKey[0], hashKey[1], hashKey[2], hashKey[3],
        hashKey[4], hashKey[5], hashKey[6], hashKey[7],
        hashKey[8], hashKey[9], hashKey[10], hashKey[11]);

    session = HashGet(self.sessionHash, hashKey, hashKeylen);
    return session;
}

UpfSRRNode * UpfSrrFindByPdrId(UpfSession *sess, uint16_t pdrId) {
    UpfSRRNode *Node;

    if (ListIsEmpty(&sess->srrList))
        return NULL;

    //TODO: Lock to protect the srrList
    Node = ListFirst(&(sess)->srrList);
    while (Node != (UpfSRRNode *)&(sess)->srrList) {
        if (Node->pdrId == pdrId)
            return Node;
        Node = (UpfSRRNode *)ListNext(Node);
    }
    return NULL;
}

UpfSRRNode * UpfSrrFindBySeqId(UpfSession *sess, uint32_t seqId) {
    UpfSRRNode *Node;
    uint8_t i;

    if (ListIsEmpty(&sess->srrList)) {
        UTLT_Error("%s: SRR List is Empty", __func__);
        return NULL;
    }

    //TODO: Lock to protect the srrList
    Node = ListFirst(&(sess)->srrList);
    while (Node != (UpfSRRNode *)&(sess)->srrList) {
        for (i = 0; i < Node->seqCount; i++) {
            if (Node->seqId[i] == seqId) {
                return Node;
            }
        }
        Node = (UpfSRRNode *)ListNext(Node);
    }

    return NULL;
}

void UpfSrrTimeoutHandler(union sigval sv);
void UpfSrrAddNode(UpfSession *sess, UpfSRRNode *node) {
    ListHeadInit(&node->node);
    //TODO: Lock to protect the srrList
    ListInsertTail(&node->node, &sess->srrList);
    node->timerCount = 0;
    UpfCreateAndStartTimer(&node->timer, UpfSrrTimeoutHandler, 1, (void *) node);
}

void UpfSrrRemoveNode(UpfSRRNode *node) {
    if (node->state == SRR_STATE_TIMER) {
        node->state = SRR_STATE_RELEASE;
        UpfDeleteTimer(&node->timer);
    }
    //TODO: Lock to protect the srrList
    ListRemove(node);
    free(node);
}

void UpfSrrRemoveAllNode(UpfSession *sess) {
    UpfSRRNode *Node, *nextNode;

    if (ListIsEmpty(&sess->srrList))
        return;

    //TODO: Lock to protect the srrList
    Node = ListFirst(&sess->srrList);
    while (Node != (UpfSRRNode *) &sess->srrList) {
        nextNode = (UpfSRRNode *) ListNext(Node);
        UpfSrrRemoveNode(Node);
        Node = nextNode;
    }
}

/* 
 * This function will add a new session or get existing session
 * */
UpfSession * UpfSessionAddByMessage(PfcpMessage *message) {
    UpfSession *session = NULL;
    PfcpFSeid *fseidPeer = NULL;

    PFCPSessionEstablishmentRequest *request =
        &message->pFCPSessionEstablishmentRequest;

    if (!request->nodeID.presence) {
        UTLT_Error("SessAddMsg: NodeID not present in SessEstReq");
        return NULL;
    }

    if (!request->cPFSEID.presence) {
        UTLT_Error("SessAddMsg: F-SEID not present in SessEstReq");
        return NULL;
    }  
   
    if (!request->createPDR[0].presence) {
        UTLT_Error("SessAddMsg: PDR not present in SessEstReq");
        return NULL;
    }

    if (!request->createFAR[0].presence) {
        UTLT_Error("SessAddMsg: FAR not present in SessEstReq");
        return NULL;
    }

    // TODO: More protocol validation before accept the session creation by
    // using the PFCP Session Establishment Request    
    fseidPeer = (PfcpFSeid *) request->cPFSEID.value;
    session = UpfSessionFindByPeerFseid(fseidPeer);
    /* It may happen to receive session establishment request
     * when UPF didn't send response due to internal error or
     * external error such packet drop in link, ...
     * */
    UTLT_Assert(!session, return NULL, "SessAddMsg: session is already there!?");
    session = UpfSessionAdd(fseidPeer);
    UTLT_Assert(session, return NULL, "SessAddMsg: Failled");
    UTLT_Debug("SessAddMsg: Success! SEID: %llx", session->upfSeid);

    return session;
}

/* --------------------------------------------------------------------------
 *                          UPF Timer
 * --------------------------------------------------------------------------
 * */
void UpfSrrTimeoutHandler(union sigval sv) {
    UpfSRRNode *node = sv.sival_ptr;
    Status status;

    if (node->state == SRR_STATE_SENT) {
        node->state = SRR_STATE_TIMER;
    } else if (node->state != SRR_STATE_TIMER) {
        return;
    } 

    status = EventSend(Self()->eventQ, UPF_EVENT_SESSION_REPORT, 4,
        node->sess, node->seid, node->pdrId, SRR_STATE_TIMER);
    UTLT_Assert(status == STATUS_OK, , "DL data message event send to N4 failed");

    ++node->timerCount;
    if (node->timerCount > SRR_MAX_TIMEOUT_COUNT) {
        node->state = SRR_STATE_TIMEOUT;
        UpfDeleteTimer(&node->timer);
        return;
    }

    UpfModifyTimerInSec(&node->timer, 1);
}
