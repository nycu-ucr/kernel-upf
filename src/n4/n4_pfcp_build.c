#define TRACE_MODULE _n4_pfcp_build

#include <stdint.h>
#include <endian.h>
#include <string.h>
#include <arpa/inet.h>

#include "upf_context.h"
#include "utlt_buff.h"
#include "pfcp_message.h"
#include "pfcp_convert.h"

#include "n4_pfcp_build.h"

#include "updk/env.h"

Status UpfN4BuildSessionEstablishmentResponse(Bufblk **bufBlk, uint8_t type,
    UpfSession *session, uint8_t cause,
    PFCPSessionEstablishmentRequest *establishRequest) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPSessionEstablishmentResponse *response = NULL;
    PfcpFSeid fSeid;
    PfcpNodeId nodeId;
    int len;

    response = &pfcpMessage.pFCPSessionEstablishmentResponse;
    memset(&pfcpMessage, 0, sizeof(pfcpMessage));

    /* Node Id */
    response->nodeID.presence = 1;
    /* TODO: IPv6 */
    memcpy(&nodeId, &Self()->pfcpNodeId, sizeof(nodeId));
    response->nodeID.len = PFCP_NODE_ID_LEN(nodeId);
    response->nodeID.value = &nodeId;

    /* cause */
    response->cause.presence = 1;
    response->cause.len = 1;
    response->cause.value = &cause;

    /* Condition or Option */
    if (cause == PFCP_CAUSE_REQUEST_ACCEPTED) {
        /* F-SEID */
        memset(&fSeid, 0, sizeof(fSeid));
        response->uPFSEID.presence = 1;
        response->uPFSEID.value = &fSeid;
        fSeid.seid = htobe64(session->upfSeid);
        status = PfcpSockaddrToFSeid(Self()->pfcpAddr,
            NULL, &fSeid, &len);
        response->uPFSEID.len = len;

        /* FQ-CSID */
    }

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlk, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "BuildSessEst: Failed to build response");

    UTLT_Debug("BuildSessEst: Success to build response!!!");
    return STATUS_OK;
}

Status UpfN4BuildSessionModificationResponse(Bufblk **bufBlkPtr, uint8_t type,
    UpfSession *session, PFCPSessionModificationRequest *modifyRequest) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPSessionModificationResponse *response = NULL;
    uint8_t cause;

    response = &pfcpMessage.pFCPSessionModificationResponse;
    memset(&pfcpMessage, 0, sizeof(pfcpMessage));

    /* cause */
    response->cause.presence = 1;
    cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    response->cause.value = &cause;
    response->cause.len = 1;

    /* TODO: Set Offending IE, Create PDR, Load Control Information, Overload Control Information, Usage Report, Failed Rule ID, Additional Usage Reports Information, Created/Updated Traffic Endpoint */

    pfcpMessage.header.type = type;
    pfcpMessage.header.seidP = 1;
    pfcpMessage.header.seid = session->smfSeid;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "SessionModBuild: Failed to build response");

    UTLT_Debug("SessionModBuild: Success to build response");
    return STATUS_OK;
}

Status UpfN4BuildSessionDeletionResponse(Bufblk **bufBlkPtr, uint8_t type,
    UpfSession *session, PFCPSessionDeletionRequest *deletionRequest) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPSessionDeletionResponse *response = NULL;
    uint8_t cause;

    response = &pfcpMessage.pFCPSessionDeletionResponse;
    memset(&pfcpMessage, 0, sizeof(PfcpMessage));

    response->cause.presence = 1;
    cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    response->cause.value = &cause;
    response->cause.len = 1;

    /* TODO: Set Offending IE, Load Control Information, Overload Control Information, 
     * Usage Report 
     * */

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "SessionDel: Failed to build response");

    UTLT_Debug("SessionDel: Success to build response");
    return STATUS_OK;
}

Status UpfN4BuildSessionReportRequestDownlinkDataReport(Bufblk **bufBlkPtr,
    uint8_t type, UpfSession *session, uint16_t pdrId) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPSessionReportRequest *request = NULL;
    PfcpReportType reportType;
    PfcpDownlinkDataServiceInformation downlinkDataServiceInformationValue;

    request = &pfcpMessage.pFCPSessionReportRequest;
    memset(&pfcpMessage, 0, sizeof(PfcpMessage));
    memset(&reportType, 0, sizeof(PfcpReportType));
    memset(&downlinkDataServiceInformationValue, 0,
           sizeof(PfcpDownlinkDataServiceInformation));

    reportType.dldr = 1;

    request->reportType.presence = 1;
    request->reportType.value = &reportType;
    request->reportType.len = sizeof(PfcpReportType);

    /* TODO: fill in downlinkDataReport */
    DownlinkDataReport *downlinkDataReport = &request->downlinkDataReport;
    downlinkDataReport->presence = 1;

    downlinkDataReport->pDRID.presence = 1;
    // This value is store in network type
    pdrId = htons(pdrId);
    downlinkDataReport->pDRID.value = &pdrId;
    downlinkDataReport->pDRID.len = sizeof(pdrId);
    // not support yet, TODO
    downlinkDataReport->downlinkDataServiceInformation.presence = 0;

    /* fill in downlinkDataServiceInformation in downlinkDataReport */
    /*
      DownlinkDataServiceInformation *downlinkDataServiceInformation =
      &downlinkDataReport->downlinkDataServiceInformation;
      // fill in value of downlinkDataServiceInformation
      downlinkDataServiceInformationValue.ppi = 0;
      downlinkDataServiceInformationValue.qfii = 0;
      downlinkDataServiceInformationValue.pagingPolicyIndicationValue = 0;
      downlinkDataServiceInformationValue.qfi = 0;
      // fill value back to ServiceInformation
      downlinkDataServiceInformation->presence = 1;
      downlinkDataServiceInformation->value =
      &downlinkDataServiceInformationValue;
      downlinkDataServiceInformation->len =
      PfcpDownlinkDataServiceInformationLen(downlinkDataServiceInformationValue);
    */

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "SRRBuild: Failed to build response");

    UTLT_Debug("SRRBuild: Success to build response");
    return STATUS_OK;
}

Status UpfN4BuildAssociationSetupResponse(Bufblk **bufBlkPtr, uint8_t type) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPAssociationSetupResponse *response = NULL;
    uint8_t cause;
    uint16_t upFunctionFeature;

    response = &pfcpMessage.pFCPAssociationSetupResponse;
    memset(&pfcpMessage, 0, sizeof(PfcpMessage));
    pfcpMessage.pFCPAssociationSetupResponse.presence = 1;

    /* node id */
    // TODO: IPv6
    response->nodeID.presence = 1;
    PfcpNodeId nodeId;
    memcpy(&nodeId, &Self()->pfcpNodeId, sizeof(nodeId));
    response->nodeID.len = PFCP_NODE_ID_LEN(nodeId);
    response->nodeID.value = &nodeId;
    UTLT_Debug("nodeID type=%d, len=%d\n", nodeId.type, PFCP_NODE_ID_LEN(nodeId));
    UTLT_Debug("nodeID addr(4)=%02x %02x %02x %02x\n",
        nodeId.fqdn[0], nodeId.fqdn[1], nodeId.fqdn[2], nodeId.fqdn[3]);

    /* cause */
    cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    response->cause.presence = 1;
    response->cause.value = &cause;
    response->cause.len = 1;

    /* Recovery Time Stamp */
    response->recoveryTimeStamp.presence = 1;
    response->recoveryTimeStamp.value = &Self()->recoveryTime;
    response->recoveryTimeStamp.len = 4;

    // TODO: support UP Function Feature report
    /* UP Function Feature (Condition) */
    upFunctionFeature = 0;
    if (upFunctionFeature) {
        response->uPFunctionFeatures.presence = 1;
        response->uPFunctionFeatures.value = &upFunctionFeature;
        response->uPFunctionFeatures.len = 2;
    } else {
        response->uPFunctionFeatures.presence = 0;
    }

    PfcpUserPlaneIpResourceInformation upIpResourceInformation;
    memset(&upIpResourceInformation, 0,
           sizeof(PfcpUserPlaneIpResourceInformation));

    // teid
    upIpResourceInformation.teidri = 1;
    upIpResourceInformation.teidRange = 0;

    // network instence
    upIpResourceInformation.assoni = 1;
    DNN *dnn;
    uint8_t dnnLen = 0;
    EnvParamsForEachDNN(dnn, Self()->envParams) {
        dnnLen = strlen(dnn->name);
        memcpy(upIpResourceInformation.networkInstance, &dnnLen, 1);
        memcpy(upIpResourceInformation.networkInstance + 1, dnn->name, dnnLen + 1);
        break;
    }

    // TODO: better algo. to select establish IP
    int isIpv6 = 0;
    VirtualPort *port;
    VirtualDeviceForEachVirtualPort(port, Self()->envParams->virtualDevice) {
        isIpv6 = (strchr(port->ipStr, ':') ? 1 : 0);
        if (!upIpResourceInformation.v4 && !isIpv6) {
            UTLT_Assert(inet_pton(AF_INET, port->ipStr, &upIpResourceInformation.addr4) == 1,
                continue, "IP address[%s] in VirtualPort is invalid", port->ipStr);
            upIpResourceInformation.v4 = 1;
        }
        /* TODO: IPv6
        if (!upIpResourceInformation.v6 && isIpv6) {
            UTLT_Assert(inet_pton(AF_INET6, port->ipStr, &upIpResourceInformation.addr6) == 1,
                continue, "IP address[%s] in VirtualPort is invalid", port->ipStr);
            upIpResourceInformation.v6 = 1;
        }
        */
        if (upIpResourceInformation.v4 && upIpResourceInformation.v6)
            break;
    }

    response->userPlaneIPResourceInformation.presence = 1;
    response->userPlaneIPResourceInformation.value = &upIpResourceInformation;
    // TODO: this is only IPv4, no network instence, no source interface
    response->userPlaneIPResourceInformation.len = 2+4+1+dnnLen;
    // HACK: sizeof(Internet) == 8, hardcord
    //response->userPlaneIPResourceInformation.len =
    //sizeof(PfcpUserPlaneIpResourceInformation);

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(*bufBlkPtr, , "buff NULL");
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "AssSetupBuild: Failed to build response");

    UTLT_Debug("AssSetupBuild: Success to build response");
    return STATUS_OK;
}

Status UpfN4BuildAssociationReleaseResponse(Bufblk **bufBlkPtr, uint8_t type) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPAssociationReleaseResponse *response = NULL;
    PfcpNodeId nodeId;
    uint8_t cause;

    response = &pfcpMessage.pFCPAssociationReleaseResponse;
    memset(&pfcpMessage, 0, sizeof(PfcpMessage));
    response->presence = 0;

    /* nodeId */
    response->nodeID.presence = 1;
    // TODO: IPv6 version
    memcpy(&nodeId, &Self()->pfcpNodeId, sizeof(nodeId));
    response->nodeID.len = PFCP_NODE_ID_LEN(nodeId);
    response->nodeID.value = &nodeId;

    /* cause */
    response->cause.presence = 1;
    cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    response->cause.value = &cause;
    response->cause.len = 1;

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "AssRelBuild: Failed to build response");

    UTLT_Debug("AssRelBuild: Success to build response");
    return STATUS_OK;
}

Status UpfN4BuildHeartbeatResponse(Bufblk **bufBlkPtr, uint8_t type) {
    Status status;
    PfcpMessage pfcpMessage;
    HeartbeatResponse *response;
    
    response = &pfcpMessage.heartbeatResponse;
    memset(&pfcpMessage, 0, sizeof(PfcpMessage));

    /* Set Recovery Time Stamp */
    response->recoveryTimeStamp.presence = 1;
    response->recoveryTimeStamp.value = &Self()->recoveryTime;
    response->recoveryTimeStamp.len = 4;

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "HeartBBuild: Failed to build response");

    UTLT_Debug("HeartBBuild: Success to build response");
    return STATUS_OK;
}
