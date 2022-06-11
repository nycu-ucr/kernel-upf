#define TRACE_MODULE _n4_pfcp_handler

#include <endian.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "utlt_list.h"
#include "utlt_network.h"

#include "upf_context.h"
#include "pfcp_message.h"
#include "pfcp_xact.h"
#include "pfcp_convert.h"
#include "n4_pfcp_build.h"
#include "up/up_path.h"

#include "updk/rule.h"
#include "updk/rule_pdr.h"
#include "updk/rule_far.h"
#include "updk/rule_qer.h"

#define REQUEST_HANDLE      0x0001
#define REQUEST_RESPONSE    0x0002
#define REQUEST_DROP        0x0004

static uint16_t ValidateUpfSessionState(UpfSession *sess, uint8_t type, uint32_t sqn) 
{ 
    uint16_t status = REQUEST_HANDLE;
    SessionReqState *reqState;
    int stateIndex;

    ConvertReqTypeToStateIndex(type, stateIndex);
    
    if (stateIndex > PFCP_MAX_REQ_STATE) {
        UTLT_Error("ValUpfSessState: request type: %u index error", type);
        return status;
    }

    reqState = &sess->reqState[stateIndex];
    switch (reqState->state) {
    case SMF_UPF_SESSION_STATE_INIT:    /* New Request */
        reqState->sqn = sqn;
        status = REQUEST_HANDLE;
        break;
    case SMF_UPF_SESSION_STATE_HANDLE: /* Outstanding request exists, and in-progress */
        if (reqState->sqn != sqn) {
            UTLT_Warning("ValUpfSessState: Type: %u Sqn O: %u N: %u", type,
                reqState->sqn, sqn);
            /* TODO: necessary action when existing sequence number is different
             * with given value
             * */
        }
        
        if (reqState->subState != SMF_UPF_SESSION_SUB_STATE_HANDLE_SUCCESS)
            status = REQUEST_HANDLE;
        else 
            status = REQUEST_DROP;
        break;
    case SMF_UPF_SESSION_STATE_SEND_RSP:
        status = REQUEST_RESPONSE;
        break;
    case SMF_UPF_SESSION_STATE_DELETED: 
    case SMF_UPF_SESSION_STATE_RELEASE:
    case SMF_UPF_SESSION_STATE_ERROR:
    default:
        status = REQUEST_HANDLE;
        break;
    }       
    return status;
}

static uint32_t GetPfcpRequestSqn(PfcpHeader *header) 
{
    if (header->seidP) {
        return be32toh(header->sqn);
    } 
    
    return be32toh(header->sqn_only);
}

void UpdateUpfSessionState(UpfSession *sess, uint8_t type, 
    uint16_t state, uint16_t substate) {
    SessionReqState *reqState;
    int stateIndex;

    ConvertReqTypeToStateIndex(type, stateIndex);
    
    if (stateIndex > PFCP_MAX_REQ_STATE) {
        UTLT_Error("UpdUpfSessState: request type: %u map index error", type);
        return;
    }
    
    reqState = &sess->reqState[stateIndex];
    reqState->state = state;
    reqState->subState = substate;
}

/*
 * Note: When apply a IE from PDR or FAR, you should check all
 * "_Convert*TlvToRule" if they need to be modified.
 * 
 * PDR: "_ConvertCreatePDRTlvToRule", "_ConvertUpdatePDRTlvToRule"
 * FAR: "_ConvertCreateFARTlvToRule", "_ConvertUpdateFARTlvToRule"
 */

Status _ConvertCreatePDRTlvToRule(UpfPDR *upfPdr, CreatePDR *createPdr) {
    UTLT_Assert(upfPdr && createPdr, return STATUS_ERROR,
        "UpfPDR or CreatePDR pointer should not be NULL");

    char ipStr[INET6_ADDRSTRLEN];
    struct in_addr *ipv4Ptr;
    struct in6_addr *ipv6Ptr;

    if (createPdr->pDRID.presence) {
        upfPdr->flags.pdrId = 1;
        upfPdr->pdrId = ntohs(*((uint16_t *)createPdr->pDRID.value));
        UTLT_Debug("PDR ID: %u", upfPdr->pdrId);
    }

    if (createPdr->precedence.presence) {
        upfPdr->flags.precedence = 1;
        upfPdr->precedence = ntohl(*((uint32_t *)createPdr->precedence.value));
        UTLT_Debug("PDR Precedence: %u", upfPdr->precedence);
    }

    if (createPdr->pDI.presence) {
        upfPdr->flags.pdi = 1;
        PDI *pdi = &createPdr->pDI;
        UPDK_PDI *updkPdi = &upfPdr->pdi;

        if (pdi->sourceInterface.presence) {
            updkPdi->flags.sourceInterface = 1;
            updkPdi->sourceInterface = *((uint8_t *)(pdi->sourceInterface.value));
            UTLT_Debug("PDI Source Interface: %u", updkPdi->sourceInterface);
        }

        if (pdi->localFTEID.presence) {
            updkPdi->flags.fTeid = 1;
            UPDK_FTEID *updkFTeid = &updkPdi->fTeid;
            PfcpFTeid *fTeid = (PfcpFTeid *)createPdr->pDI.localFTEID.value;
            
            // Copy flags in F-TEID
            memcpy(updkFTeid, fTeid, sizeof(uint8_t));

            updkFTeid->teid = ntohl(fTeid->teid);
            UTLT_Debug("F-TEID TEID: %u", updkFTeid->teid);

            if (fTeid->v4 && fTeid->v6) {
                ipv4Ptr = &fTeid->dualStack.addr4;
                ipv6Ptr = &fTeid->dualStack.addr6;
            } else {
                ipv4Ptr = &fTeid->addr4;
                ipv6Ptr = &fTeid->addr6;
            }

            if (fTeid->v4) {
                updkFTeid->ipv4 = *ipv4Ptr;
                inet_ntop(AF_INET, &updkFTeid->ipv4, ipStr, INET_ADDRSTRLEN);
                UTLT_Debug("F-TEID IPv4: %s", ipStr);
            }

            if (fTeid->v6) {
                updkFTeid->ipv6 = *ipv6Ptr;
                inet_ntop(AF_INET6, &updkFTeid->ipv6, ipStr, INET6_ADDRSTRLEN);
                UTLT_Debug("F-TEID IPv6: %s", ipStr);
            }

            if (fTeid->chid) {
                updkFTeid->chooseId = fTeid->chooseId;
                UTLT_Debug("F-TEID Choose ID: %u", updkFTeid->chooseId);
            }
        }

        if (pdi->uEIPAddress.presence) {
            updkPdi->flags.ueIpAddress = 1;
            UPDK_UEIPAddress *updkUeIpAddresss = &updkPdi->ueIpAddress;
            PfcpUeIpAddr *ueIp = (PfcpUeIpAddr*)createPdr->pDI.uEIPAddress.value;

            // Copy flags in UE IP Address
            memcpy(updkUeIpAddresss, ueIp, sizeof(uint8_t));

            if (ueIp->v4 && ueIp->v6) {
                ipv4Ptr = &ueIp->dualStack.addr4;
                ipv6Ptr = &ueIp->dualStack.addr6;
            } else {
                ipv4Ptr = &ueIp->addr4;
                ipv6Ptr = &ueIp->addr6;
            }

            if (ueIp->v4) {
                updkUeIpAddresss->ipv4 = *ipv4Ptr;
                inet_ntop(AF_INET, &updkUeIpAddresss->ipv4, ipStr, INET_ADDRSTRLEN);
                UTLT_Debug("UE IP Address IPv4: %s", ipStr);
            }

            if (ueIp->v6) {
                updkUeIpAddresss->ipv6 = *ipv6Ptr;
                inet_ntop(AF_INET6, &updkUeIpAddresss->ipv6, ipStr, INET6_ADDRSTRLEN);
                UTLT_Debug("UE IP Address IPv6: %s", ipStr);
            }

            if (ueIp->ipv6d) {
                updkUeIpAddresss->ipv6PrefixDelegationBit = ueIp->ipv6PrefixDelegationBit;
                UTLT_Debug("UE IP Address IPv6 Prefix Delegation Bit: %u", ipStr);
            }
        }

        if (pdi->sDFFilter.presence) {
            updkPdi->flags.sdfFilter = 1;
            UPDK_SDFFilter *updkSdfFilter = &updkPdi->sdfFilter;
            PfcpSDFFilterDescription *des = (PfcpSDFFilterDescription*) pdi->sDFFilter.value;

            // Copy flags in UE IP Address
            memcpy(updkSdfFilter, des, sizeof(uint8_t));

            for (size_t idx = 2; idx < createPdr->pDI.sDFFilter.len; /* Do nothing here */) {
                if (des->fd) {
                    // TODO: Need to Check if it is correct
                    updkSdfFilter->lenOfFlowDescription = ntohs(*(uint16_t *) ((uint8_t *) pdi->sDFFilter.value + idx));

                    // TODO: dynamic alloc?
                    UTLT_Assert(sizeof(updkSdfFilter->flowDescription) > updkSdfFilter->lenOfFlowDescription,
                        continue, "Need more space to store Flow Description");
                    
                    strncpy(updkSdfFilter->flowDescription, pdi->sDFFilter.value+idx+2,
                       updkSdfFilter->lenOfFlowDescription);
                    
                    idx += 2 + updkSdfFilter->lenOfFlowDescription;

                    UTLT_Debug("SDF Filter Flow Description: %s", updkSdfFilter->flowDescription);
                } else if (des->ttc) {
                    updkSdfFilter->tosTrafficClass = ntohs(*(uint16_t *)((uint8_t *) pdi->sDFFilter.value+idx));
                    idx += 2;

                    UTLT_Debug("SDF Filter ToS Traffic Class: %u", updkSdfFilter->tosTrafficClass);
                } else if (des->spi) {
                    updkSdfFilter->securityParameterIndex = ntohl(*(uint32_t *)((uint8_t *) pdi->sDFFilter.value+idx));
                    idx += 4;

                    UTLT_Debug("SDF Filter Security Parameter Index: %u", updkSdfFilter->securityParameterIndex);
                } else if (des->fl) {
                    memcpy(updkSdfFilter->flowLabel, (uint8_t *) pdi->sDFFilter.value+idx, sizeof(char) * 3);
                    idx += 3;

                    UTLT_Debug("SDF Filter Flow Label: %c%c%c",
                        updkSdfFilter->flowLabel[0], updkSdfFilter->flowLabel[2], updkSdfFilter->flowLabel[3]);
                } else if (des->bid) {
                    updkSdfFilter->sdfFilterId = ntohl(*(uint32_t*)((uint8_t*)createPdr->pDI.sDFFilter.value+idx));
                    UTLT_Debug("SDF Filter SDF Filter Id: %u", updkSdfFilter->sdfFilterId);
                    idx += 4;
                } else {
                    UTLT_Warning("Other tag not implements");
                    idx++;
                }
            }
        }
    }

    if (createPdr->outerHeaderRemoval.presence) {
        upfPdr->flags.outerHeaderRemoval = 1;
        upfPdr->outerHeaderRemoval = *((uint8_t *)(createPdr->outerHeaderRemoval.value));
        UTLT_Debug("PDR Outer Header Removal: %u", upfPdr->outerHeaderRemoval);
    }

    if (createPdr->fARID.presence) {
        upfPdr->flags.farId = 1;
        upfPdr->farId = ntohl(*((uint32_t *)createPdr->fARID.value));
        UTLT_Debug("PDR FAR ID: %u", upfPdr->farId);
    }

    if (createPdr->uRRID.presence) {
        // TODO: Need to handle multiple URR
        /*
        upfPdr->flags.urrId = 1;
        upfPdr->urrId = ntohl(*((uint32_t *)createPdr->uRRID.value));
        UTLT_Debug("PDR URR ID: %u", upfPdr->farId);
        */
        UTLT_Warning("UPF do NOT support URR yet");
    }

	//TODO: Support Multiple QERs, currently 4QERs only
    for (int i = 0; i < sizeof(createPdr->qERID) / sizeof(QERID); i++) {
        if (createPdr->qERID[i].presence) {
            upfPdr->flags.qerId = 1;
            upfPdr->qerId[i] = ntohl(*((uint32_t *)createPdr->qERID[i].value));
            UTLT_Trace("PDR QER ID: %u", upfPdr->qerId[i]);
        }
    }

    if (createPdr->activatePredefinedRules.presence) {
        // TODO: Need to support
        UTLT_Warning("UPF do NOT support Activate Predefined Rules yet");
    }

    return STATUS_OK;
}

Status UpfN4HandleCreatePdr(UpfSession *session, CreatePDR *createPdr) {
    UTLT_Debug("Handle Create PDR");

    UTLT_Assert(createPdr->pDRID.presence, return STATUS_ERROR,
                "pdr id not presence");
    UTLT_Assert(createPdr->precedence.presence, return STATUS_ERROR,
                "precedence not presence");
    UTLT_Assert(createPdr->pDI.presence, return STATUS_ERROR,
                "Pdi not exist");
    UTLT_Assert(createPdr->pDI.sourceInterface.presence,
                return STATUS_ERROR, "PDI SourceInterface not presence");

    UpfPDR upfPdr;
    memset(&upfPdr, 0, sizeof(UpfPDR));

    uint16_t pdrID = ntohs(*((uint16_t*) createPdr->pDRID.value));
    UTLT_Assert(UpfPDRFindByID(pdrID, &upfPdr), return STATUS_ERROR, "PDR ID[%u] does exist in UPF Context", pdrID);

    UTLT_Assert(_ConvertCreatePDRTlvToRule(&upfPdr, createPdr) == STATUS_OK,
        return STATUS_ERROR, "Convert PDR TLV To Rule is failed");

    // Using UPDK API
    UTLT_Assert(Gtpv1TunnelCreatePDR(&upfPdr) == 0, return STATUS_ERROR,
        "Gtpv1TunnelCreatePDR failed");

    // Register PDR to Session
    UTLT_Assert(UpfPDRRegisterToSession(session, &upfPdr),
        return STATUS_ERROR, "UpfPDRRegisterToSession failed");

    // Set buff relate pdr to session
    UpfBufPacketAdd(session, pdrID);

    return STATUS_OK;
}

Status _ConvertCreateFARTlvToRule(UpfFAR *upfFar, CreateFAR *createFar) {
    UTLT_Assert(upfFar && createFar, return STATUS_ERROR,
        "UpfFAR or CreateFAR pointer should not be NULL");

    char ipStr[INET6_ADDRSTRLEN];

    if (createFar->fARID.presence) {
        upfFar->flags.farId = 1;
        upfFar->farId = ntohl(*((uint32_t *)createFar->fARID.value));
        UTLT_Debug("FAR ID: %u", upfFar->farId);
    }

    if (createFar->applyAction.presence) {
        upfFar->flags.applyAction = 1;
        upfFar->applyAction = *((uint8_t *)(createFar->applyAction.value));
        UTLT_Debug("FAR Apply Action: %u", upfFar->applyAction);
    }

    if (createFar->forwardingParameters.presence) {
        upfFar->flags.forwardingParameters = 1;
        ForwardingParameters *forwardingParameters = &createFar->forwardingParameters;
        UPDK_ForwardingParameters *updkForwardingParameters = &upfFar->forwardingParameters;

        if (forwardingParameters->destinationInterface.presence) {
            updkForwardingParameters->flags.destinationInterface = 1;
            updkForwardingParameters->destinationInterface = *((uint8_t *)(createFar->forwardingParameters.destinationInterface.value));
            UTLT_Debug("Forwarding Parameters Destination Interface: %u", updkForwardingParameters->destinationInterface);
        }

        if (forwardingParameters->networkInstance.presence) {
            updkForwardingParameters->flags.networkInstance = 1;
            UTLT_Assert(forwardingParameters->networkInstance.len < sizeof(updkForwardingParameters->networkInstance),
                return STATUS_ERROR, "Need more space to store Network Instance in FAR");
            strncpy(updkForwardingParameters->networkInstance, forwardingParameters->networkInstance.value,
                forwardingParameters->networkInstance.len);
            UTLT_Debug("Forwarding Parameters Network Instance: %u", updkForwardingParameters->destinationInterface);
        }

        if (forwardingParameters->outerHeaderCreation.presence) {
            updkForwardingParameters->flags.outerHeaderCreation = 1;
            PfcpOuterHdr *outerHdr = (PfcpOuterHdr *) (forwardingParameters->outerHeaderCreation.value);
            UPDK_OuterHeaderCreation *updkOuterHeaderCreation = &updkForwardingParameters->outerHeaderCreation;

            updkOuterHeaderCreation->description = *((uint8_t *) outerHdr);
            UTLT_Debug("Outer Header Creation Description: %u", updkOuterHeaderCreation->description);

            if (outerHdr->gtpuIpv4 || outerHdr->gtpuIpv6) {
                updkOuterHeaderCreation->teid = ntohl(outerHdr->teid);
                UTLT_Debug("Outer Header Creation TEID: %u", updkOuterHeaderCreation->teid);
            }

            if (outerHdr->udpIpv4 || outerHdr->gtpuIpv4) {
                updkOuterHeaderCreation->ipv4 = outerHdr->addr4;
                inet_ntop(AF_INET, &updkOuterHeaderCreation->ipv4, ipStr, INET_ADDRSTRLEN);
                UTLT_Debug("Outer Header Creation IPv4: %s", ipStr);

                if (!outerHdr->gtpuIpv4) {
                    updkOuterHeaderCreation->port = ntohs(outerHdr->port);
                    UTLT_Debug("Outer Header Creation Port: %u", updkOuterHeaderCreation->port);
                }
            }

            if (outerHdr->udpIpv6 || outerHdr->gtpuIpv6) {
                updkOuterHeaderCreation->ipv6 = outerHdr->addr6;
                inet_ntop(AF_INET6, &updkOuterHeaderCreation->ipv6, ipStr, INET6_ADDRSTRLEN);
                UTLT_Debug("Outer Header Creation IPv6: %s", ipStr);

                if (!outerHdr->gtpuIpv6) {
                    updkOuterHeaderCreation->port = ntohs(outerHdr->port);
                    UTLT_Debug("Outer Header Creation Port: %u", updkOuterHeaderCreation->port);
                }
            }
        }

        if (forwardingParameters->forwardingPolicy.presence) {
            updkForwardingParameters->flags.forwardingPolicy = 1;
            uint8_t *forwardingPolicy = forwardingParameters->forwardingPolicy.value;
            UPDK_ForwardingPolicy *updkForwardingPolicy = &updkForwardingParameters->forwardingPolicy;

            updkForwardingPolicy->forwardingPolicyIdentifierLength = forwardingPolicy[0];
            UTLT_Assert(forwardingPolicy[0] < sizeof(updkForwardingPolicy->forwardingPolicyIdentifier), return STATUS_ERROR,
                "Forwarding Policy Identifier is too long");
            memcpy(updkForwardingPolicy->forwardingPolicyIdentifier, &forwardingPolicy[1], forwardingPolicy[0]);
            updkForwardingPolicy->forwardingPolicyIdentifier[forwardingPolicy[0]] = 0;
        }
    }

    return STATUS_OK;
}

Status UpfN4HandleCreateFar(UpfSession *session, CreateFAR *createFar) {
    UTLT_Debug("Handle Create FAR");

    UTLT_Assert(createFar->fARID.presence, return STATUS_ERROR,
                "Far ID not presence");
    UTLT_Assert(createFar->applyAction.presence,
                return STATUS_ERROR, "Apply Action not presence");

    UpfFAR upfFar;
    memset(&upfFar, 0, sizeof(UpfFAR));

    uint32_t farID = ntohl(*((uint32_t*) createFar->fARID.value));
    UTLT_Assert(UpfFARFindByID(farID, &upfFar), return STATUS_ERROR, "FAR ID[%u] does exist in UPF Context", farID);

    UTLT_Assert(_ConvertCreateFARTlvToRule(&upfFar, createFar) == STATUS_OK,
        return STATUS_ERROR, "Convert FAR TLV To Rule is failed");

    // Using UPDK API
    UTLT_Assert(Gtpv1TunnelCreateFAR(&upfFar) == 0, return STATUS_ERROR,
        "Gtpv1TunnelCreateFAR failed");
    
    // Register FAR to Session
    UTLT_Assert(UpfFARRegisterToSession(session, &upfFar),
        return STATUS_ERROR, "UpfFARRegisterToSession failed");

    return STATUS_OK;
}

Status _ConvertCreateQERTlvToRule(UpfQER *upfQer, CreateQER *createQer) {
    UTLT_Assert(upfQer && createQer, return STATUS_ERROR,
        "UpfQER or CreateQER pointer should not be NULL");

    int offset;

    if (createQer->qERID.presence) {
        upfQer->flags.qerId = 1;
        upfQer->qerId = ntohl(*((uint32_t *) createQer->qERID.value));
        UTLT_Debug("QER ID: %u", QERGetID(upfQer));
    }

    if (createQer->qERCorrelationID.presence) {
        upfQer->flags.qerCorrelationId = 1;
        upfQer->qerCorrelationId = ntohl(*((uint32_t *) createQer->qERCorrelationID.value));
        UTLT_Debug("QER Correlation ID value: %u", QERGetCorrelationID(upfQer));
    }

    if (createQer->gateStatus.presence) {
        upfQer->flags.gateStatus = 1;
        upfQer->gateStatus = *((uint8_t *) createQer->gateStatus.value);
        UTLT_Debug("QER Gate Status: %u", QERGetGateStatus(upfQer));
    }

    if (createQer->maximumBitrate.presence) {
        upfQer->flags.maximumBitrate = 1;
        Pfcp5ByteBitRateToHost(createQer->maximumBitrate.value, &upfQer->maximumBitrate.ul);
        Pfcp5ByteBitRateToHost(createQer->maximumBitrate.value + sizeof(uint8_t) * 5, &upfQer->maximumBitrate.dl);
        UTLT_Debug("QER MBR UL: %u, DL: %u", QERGetMBRUL(upfQer), QERGetMBRDL(upfQer));
    }

    if (createQer->guaranteedBitrate.presence) {
        upfQer->flags.guaranteedBitrate = 1;
        Pfcp5ByteBitRateToHost(createQer->guaranteedBitrate.value, &upfQer->guaranteedBitrate.ul);
        Pfcp5ByteBitRateToHost(createQer->guaranteedBitrate.value + sizeof(uint8_t) * 5, &upfQer->guaranteedBitrate.dl);
        UTLT_Debug("QER GBR UL: %u, DL: %u", QERGetGBRUL(upfQer), QERGetGBRDL(upfQer));
    }

    if (createQer->packetRate.presence) {
        upfQer->flags.packetRate = 1;
        memcpy(&upfQer->packetRate.flags, createQer->packetRate.value, sizeof(uint8_t));
        UTLT_Debug("QER Packet Rate flags ulpr: %u, dlpr : %u",
                QERGetPacketRate(upfQer).flags.ulpr, QERGetPacketRate(upfQer).flags.dlpr);
        offset = sizeof(uint8_t);
        
        if (QERGetPacketRate(upfQer).flags.ulpr) {
            upfQer->packetRate.uplinkTimeUnit = *((uint8_t *) (createQer->packetRate.value + offset));
            upfQer->packetRate.maximumUplinkPacketRate = ntohs(*((uint16_t *) (createQer->packetRate.value + offset + 1)));
            UTLT_Debug("QER Packet Rate Uplink Time Unit: %u, Maximum Uplink Packet Rate: %u",
                    QERGetPacketRateULTimeUnit(upfQer), QERGetPacketRateMaxUL(upfQer));
            offset += 3;
        }

        if (QERGetPacketRate(upfQer).flags.dlpr) {
            upfQer->packetRate.downlinkTimeUnit = *((uint8_t *) (createQer->packetRate.value + offset));
            upfQer->packetRate.maximumDownlinkPacketRate = ntohs(*((uint16_t *) (createQer->packetRate.value + offset + 1)));
            UTLT_Debug("QER Packet Rate Downlink Time Unit: %u, Maximum Downlink Packet Rate: %u",
                    QERGetPacketRateDLTimeUnit(upfQer), QERGetPacketRateMaxDL(upfQer));
            // offset += 3;
        }
    }

    if (createQer->dLFlowLevelMarking.presence) {
        upfQer->flags.dlFlowLevelMarking = 1;
        memcpy(&upfQer->dlFlowLevelMarking.flags, createQer->dLFlowLevelMarking.value, sizeof(uint8_t));
        UTLT_Debug("QER DL Flow Level Marking flags TTC: %u, SCI: %u",
                QERGetDLFlowLevelMark(upfQer).flags.ttc, QERGetDLFlowLevelMark(upfQer).flags.sci);
        offset = sizeof(uint8_t);

        if (QERGetDLFlowLevelMark(upfQer).flags.ttc) {
            // TS 29.244 8.2.66 The ToS/Traffic Class field, when present, shall be encoded on two octets as an OctetString
            upfQer->dlFlowLevelMarking.tosTrafficClass = *((uint16_t *) (createQer->dLFlowLevelMarking.value + offset));
            UTLT_Debug("QER DL Flow Level Marking ToS/Traffic Class: %u",
                    QERGetDLFlowLevelMarkTTC(upfQer));
            offset += sizeof(uint16_t);
        }

        if (QERGetDLFlowLevelMark(upfQer).flags.sci) {
            upfQer->dlFlowLevelMarking.serviceClassIndicator = *((uint16_t *) (createQer->dLFlowLevelMarking.value + offset));
            UTLT_Debug("QER DL Flow Level Marking Service Class Indicator: %u",
                    QERGetDLFlowLevelMarkSCI(upfQer));
            // offset += sizeof(uint16_t);
        }
    }

    if (createQer->qoSFlowIdentifier.presence) {
        upfQer->flags.qosFlowIdentifier = 1;
        upfQer->qosFlowIdentifier = *((uint8_t *) (createQer->qoSFlowIdentifier.value));
        UTLT_Debug("QER QoS Flow Identifier: %u", QERGetQFI(upfQer));
    }

    if (createQer->reflectiveQoS.presence) {
        upfQer->flags.reflectiveQos = 1;
        upfQer->reflectiveQos = *((uint8_t *) (createQer->reflectiveQoS.value));
        UTLT_Debug("QER Reflective QoS: %u", QERGetRQI(upfQer));
    }

    return STATUS_OK;
}

Status UpfN4HandleCreateQer(UpfSession *session, CreateQER *createQer) {
    UTLT_Debug("Handle Create QER");

    UTLT_Assert(createQer->qERID.presence, return STATUS_ERROR,
                "Qer ID not presence");
    UTLT_Assert(createQer->gateStatus.presence,
                return STATUS_ERROR, "Gate Status not presence");

    UpfQER upfQer;
    memset(&upfQer, 0, sizeof(UpfQER));

    uint32_t qerID = ntohl(*((uint32_t *) createQer->qERID.value));
    UTLT_Assert(UpfQERFindByID(qerID, &upfQer), return STATUS_ERROR, "QER ID[%u] does exist in UPF Context", qerID);

    UTLT_Assert(_ConvertCreateQERTlvToRule(&upfQer, createQer) == STATUS_OK,
        return STATUS_ERROR, "Convert Create QER TLV To Rule is failed");

    // Using UPDK API
    UTLT_Assert(Gtpv1TunnelCreateQER(&upfQer) == 0, return STATUS_ERROR,
        "Gtpv1TunnelCreateQER failed");

    // Register QER to Session
    UTLT_Assert(UpfQERRegisterToSession(session, &upfQer),
        return STATUS_ERROR, "UpfQERRegisterToSession failed");

    return STATUS_OK;
}

Status _ConvertUpdatePDRTlvToRule(UpfPDR *upfPdr, UpdatePDR *updatePDR) {
    UTLT_Assert(upfPdr && updatePDR, return STATUS_ERROR,
        "UpfPDR or UpdatePDR pointer should not be NULL");

    char ipStr[INET6_ADDRSTRLEN];
    struct in_addr *ipv4Ptr;
    struct in6_addr *ipv6Ptr;

    if (updatePDR->pDRID.presence) {
        upfPdr->flags.pdrId = 1;
        upfPdr->pdrId = ntohs(*((uint16_t *)updatePDR->pDRID.value));
        UTLT_Debug("PDR ID: %u", upfPdr->pdrId);
    }

    if (updatePDR->precedence.presence) {
        upfPdr->flags.precedence = 1;
        upfPdr->precedence = ntohl(*((uint32_t *)updatePDR->precedence.value));
        UTLT_Debug("PDR ID: %u", upfPdr->precedence);
    }

    if (updatePDR->pDI.presence) {
        upfPdr->flags.pdi = 1;
        PDI *pdi = &updatePDR->pDI;
        UPDK_PDI *updkPdi = &upfPdr->pdi;

        if (pdi->sourceInterface.presence) {
            updkPdi->flags.sourceInterface = 1;
            updkPdi->sourceInterface = *((uint8_t *)(pdi->sourceInterface.value));
            UTLT_Debug("PDI Source Interface: %u", updkPdi->sourceInterface);
        }

        if (pdi->localFTEID.presence) {
            updkPdi->flags.fTeid = 1;
            UPDK_FTEID *updkFTeid = &updkPdi->fTeid;
            PfcpFTeid *fTeid = (PfcpFTeid *)updatePDR->pDI.localFTEID.value;
            
            // Copy flags in F-TEID
            memcpy(updkFTeid, fTeid, sizeof(uint8_t));

            updkFTeid->teid = ntohl(fTeid->teid);
            UTLT_Debug("F-TEID TEID: %u", updkFTeid->teid);

            if (fTeid->v4 && fTeid->v6) {
                ipv4Ptr = &fTeid->dualStack.addr4;
                ipv6Ptr = &fTeid->dualStack.addr6;
            } else {
                ipv4Ptr = &fTeid->addr4;
                ipv6Ptr = &fTeid->addr6;
            }

            if (fTeid->v4) {
                updkFTeid->ipv4 = *ipv4Ptr;
                inet_ntop(AF_INET, &updkFTeid->ipv4, ipStr, INET_ADDRSTRLEN);
                UTLT_Debug("F-TEID IPv4: %s", ipStr);
            }

            if (fTeid->v6) {
                updkFTeid->ipv6 = *ipv6Ptr;
                inet_ntop(AF_INET6, &updkFTeid->ipv6, ipStr, INET6_ADDRSTRLEN);
                UTLT_Debug("F-TEID IPv6: %s", ipStr);
            }

            if (fTeid->chid) {
                updkFTeid->chooseId = fTeid->chooseId;
                UTLT_Debug("F-TEID Choose ID: %u", updkFTeid->chooseId);
            }
        }

        if (pdi->uEIPAddress.presence) {
            updkPdi->flags.ueIpAddress = 1;
            UPDK_UEIPAddress *updkUeIpAddresss = &updkPdi->ueIpAddress;
            PfcpUeIpAddr *ueIp = (PfcpUeIpAddr*)updatePDR->pDI.uEIPAddress.value;

            // Copy flags in UE IP Address
            memcpy(updkUeIpAddresss, ueIp, sizeof(uint8_t));

            if (ueIp->v4 && ueIp->v6) {
                ipv4Ptr = &ueIp->dualStack.addr4;
                ipv6Ptr = &ueIp->dualStack.addr6;
            } else {
                ipv4Ptr = &ueIp->addr4;
                ipv6Ptr = &ueIp->addr6;
            }

            if (ueIp->v4) {
                updkUeIpAddresss->ipv4 = *ipv4Ptr;
                inet_ntop(AF_INET, &updkUeIpAddresss->ipv4, ipStr, INET_ADDRSTRLEN);
                UTLT_Debug("UE IP Address IPv4: %s", ipStr);
            }

            if (ueIp->v6) {
                updkUeIpAddresss->ipv6 = *ipv6Ptr;
                inet_ntop(AF_INET6, &updkUeIpAddresss->ipv6, ipStr, INET6_ADDRSTRLEN);
                UTLT_Debug("UE IP Address IPv6: %s", ipStr);
            }

            if (ueIp->ipv6d) {
                updkUeIpAddresss->ipv6PrefixDelegationBit = ueIp->ipv6PrefixDelegationBit;
                UTLT_Debug("UE IP Address IPv6 Prefix Delegation Bit: %u", ipStr);
            }
        }

        if (pdi->sDFFilter.presence) {
            updkPdi->flags.sdfFilter = 1;
            UPDK_SDFFilter *updkSdfFilter = &updkPdi->sdfFilter;
            PfcpSDFFilterDescription *des = (PfcpSDFFilterDescription*) pdi->sDFFilter.value;

            // Copy flags in UE IP Address
            memcpy(updkSdfFilter, des, sizeof(uint8_t));

            for (size_t idx = 2; idx < updatePDR->pDI.sDFFilter.len; /* Do nothing here */) {
                if (des->fd) {
                    // TODO: Need to Check if it is correct
                    updkSdfFilter->lenOfFlowDescription = ntohs(*(uint16_t *) ((uint8_t *) pdi->sDFFilter.value + idx));

                    // TODO: dynamic alloc?
                    UTLT_Assert(sizeof(updkSdfFilter->flowDescription) > updkSdfFilter->lenOfFlowDescription,
                        continue, "Need more space to store Flow Description");
                    
                    strncpy(updkSdfFilter->flowDescription, pdi->sDFFilter.value+idx+2,
                       updkSdfFilter->lenOfFlowDescription);
                    
                    idx += 2 + updkSdfFilter->lenOfFlowDescription;

                    UTLT_Debug("SDF Filter Flow Description: %s", updkSdfFilter->flowDescription);
                } else if (des->ttc) {
                    updkSdfFilter->tosTrafficClass = ntohs(*(uint16_t *)((uint8_t *) pdi->sDFFilter.value+idx));
                    idx += 2;

                    UTLT_Debug("SDF Filter ToS Traffic Class: %u", updkSdfFilter->tosTrafficClass);
                } else if (des->spi) {
                    updkSdfFilter->securityParameterIndex = ntohl(*(uint32_t *)((uint8_t *) pdi->sDFFilter.value+idx));
                    idx += 4;

                    UTLT_Debug("SDF Filter Security Parameter Index: %u", updkSdfFilter->securityParameterIndex);
                } else if (des->fl) {
                    memcpy(updkSdfFilter->flowLabel, (uint8_t *) pdi->sDFFilter.value+idx, sizeof(char) * 3);
                    idx += 3;

                    UTLT_Debug("SDF Filter Flow Label: %c%c%c",
                        updkSdfFilter->flowLabel[0], updkSdfFilter->flowLabel[2], updkSdfFilter->flowLabel[3]);
                } else if (des->bid) {
                    updkSdfFilter->sdfFilterId = ntohl(*(uint32_t*)((uint8_t*)updatePDR->pDI.sDFFilter.value+idx));
                    UTLT_Debug("SDF Filter SDF Filter Id: %u", updkSdfFilter->sdfFilterId);
                    idx += 4;
                } else {
                    UTLT_Warning("Other tag not implements");
                    idx++;
                }
            }
        }
    }

    if (updatePDR->outerHeaderRemoval.presence) {
        upfPdr->flags.outerHeaderRemoval = 1;
        upfPdr->outerHeaderRemoval = *((uint8_t *)(updatePDR->outerHeaderRemoval.value));
        UTLT_Debug("PDR Outer Header Removal: %u", upfPdr->outerHeaderRemoval);
    }

    if (updatePDR->fARID.presence) {
        upfPdr->flags.farId = 1;
        upfPdr->farId = ntohl(*((uint32_t *)updatePDR->fARID.value));
        UTLT_Debug("PDR FAR ID: %u", upfPdr->farId);
    }

    if (updatePDR->uRRID.presence) {
        // TODO: Need to handle multiple URR
        /*
        upfPdr->flags.urrId = 1;
        upfPdr->urrId = ntohl(*((uint32_t *)updatePDR->uRRID.value));
        UTLT_Debug("PDR URR ID: %u", upfPdr->farId);
        */
        UTLT_Warning("UPF do NOT support URR yet");
    }

    for (int i = 0; i < sizeof(updatePDR->qERID) / sizeof(QERID); i++) {
        if (updatePDR->qERID[i].presence) {
            upfPdr->flags.qerId = 1;
            upfPdr->qerId[i] = ntohl(*((uint32_t *)updatePDR->qERID[i].value));
            UTLT_Trace("PDR QER ID: %u", upfPdr->qerId[i]);
        }
    }

    if (updatePDR->activatePredefinedRules.presence) {
        // TODO: Need to support
        UTLT_Warning("UPF do NOT support Activate Predefined Rules yet");
    }

    if (updatePDR->deactivatePredefinedRules.presence) {
        // TODO: Need to support
        UTLT_Warning("UPF do NOT support Deactivate Predefined Rules yet");
    }

    return STATUS_OK;
}

Status UpfN4HandleUpdatePdr(UpfSession *session, UpdatePDR *updatePdr) {
    UTLT_Debug("Handle Update PDR");

    UTLT_Assert(updatePdr->pDRID.presence == 1,
                return STATUS_ERROR, "updatePDR no pdrId");

    UpfPDR upfPdr;
    memset(&upfPdr, 0, sizeof(UpfPDR));

    uint16_t pdrID = ntohs(*((uint16_t *)updatePdr->pDRID.value));
    UTLT_Assert(!UpfPDRFindByID(pdrID, &upfPdr), return STATUS_ERROR, "PDR ID[%u] does NOT exist in UPF Context", pdrID);

    UTLT_Assert(_ConvertUpdatePDRTlvToRule(&upfPdr, updatePdr) == STATUS_OK,
        return STATUS_ERROR, "Convert PDR TLV To Rule is failed");

    // Using UPDK API
    UTLT_Assert(Gtpv1TunnelUpdatePDR(&upfPdr) == 0, return STATUS_ERROR,
        "Gtpv1TunnelUpdatePDR failed");

    // Register PDR to Session
    UTLT_Assert(UpfPDRRegisterToSession(session, &upfPdr),
        return STATUS_ERROR, "UpfPDRRegisterToSession failed");

    return STATUS_OK;
}

Status _ConvertUpdateFARTlvToRule(UpfFAR *upfFar, UpdateFAR *updateFAR) {
    UTLT_Assert(upfFar && updateFAR, return STATUS_ERROR,
        "UpfFAR or UpdateFAR pointer should not be NULL");

    char ipStr[INET6_ADDRSTRLEN];

    if (updateFAR->fARID.presence) {
        upfFar->flags.farId = 1;
        upfFar->farId = ntohl(*((uint32_t *)updateFAR->fARID.value));
        UTLT_Debug("FAR ID: %u", upfFar->farId);
    }

    if (updateFAR->applyAction.presence) {
        upfFar->flags.applyAction = 1;
        upfFar->applyAction = *((uint8_t *)(updateFAR->applyAction.value));
        UTLT_Debug("FAR Apply Action: %u", upfFar->applyAction);
    }

    if (updateFAR->updateForwardingParameters.presence) {
        upfFar->flags.forwardingParameters = 1;
        UpdateForwardingParameters *forwardingParameters = &updateFAR->updateForwardingParameters;
        UPDK_ForwardingParameters *updkForwardingParameters = &upfFar->forwardingParameters;

        if (forwardingParameters->destinationInterface.presence) {
            updkForwardingParameters->flags.destinationInterface = 1;
            updkForwardingParameters->destinationInterface = *((uint8_t *)(forwardingParameters->destinationInterface.value));
            UTLT_Debug("Forwarding Parameters Destination Interface: %u", updkForwardingParameters->destinationInterface);
        }

        if (forwardingParameters->networkInstance.presence) {
            updkForwardingParameters->flags.networkInstance = 1;
            UTLT_Assert(forwardingParameters->networkInstance.len < sizeof(updkForwardingParameters->networkInstance),
                return STATUS_ERROR, "Need more space to store Network Instance in FAR");
            strncpy(updkForwardingParameters->networkInstance, forwardingParameters->networkInstance.value,
                forwardingParameters->networkInstance.len);
            UTLT_Debug("Forwarding Parameters Network Instance: %u", updkForwardingParameters->destinationInterface);
        }

        if (forwardingParameters->outerHeaderCreation.presence) {
            updkForwardingParameters->flags.outerHeaderCreation = 1;
            PfcpOuterHdr *outerHdr = (PfcpOuterHdr *) (forwardingParameters->outerHeaderCreation.value);
            UPDK_OuterHeaderCreation *updkOuterHeaderCreation = &updkForwardingParameters->outerHeaderCreation;

            updkOuterHeaderCreation->description = *((uint8_t *) outerHdr);
            UTLT_Debug("Outer Header Creation Description: %u", updkOuterHeaderCreation->description);
 
            if (outerHdr->gtpuIpv4 || outerHdr->gtpuIpv6) {
                updkOuterHeaderCreation->teid = ntohl(outerHdr->teid);
                UTLT_Debug("Outer Header Creation TEID: %u", updkOuterHeaderCreation->teid);
            }

            if (outerHdr->udpIpv4 || outerHdr->gtpuIpv4) {
                updkOuterHeaderCreation->ipv4 = outerHdr->addr4;
                inet_ntop(AF_INET, &updkOuterHeaderCreation->ipv4, ipStr, INET_ADDRSTRLEN);
                UTLT_Debug("Outer Header Creation IPv4: %s", ipStr);

                if (!outerHdr->gtpuIpv4) {
                    updkOuterHeaderCreation->port = ntohs(outerHdr->port);
                    UTLT_Debug("Outer Header Creation Port: %u", updkOuterHeaderCreation->port);
                }
            }

            if (outerHdr->udpIpv6 || outerHdr->gtpuIpv6) {
                updkOuterHeaderCreation->ipv6 = outerHdr->addr6;
                inet_ntop(AF_INET6, &updkOuterHeaderCreation->ipv6, ipStr, INET6_ADDRSTRLEN);
                UTLT_Debug("Outer Header Creation IPv6: %s", ipStr);

                if (!outerHdr->gtpuIpv6) {
                    updkOuterHeaderCreation->port = ntohs(outerHdr->port);
                    UTLT_Debug("Outer Header Creation Port: %u", updkOuterHeaderCreation->port);
                }
            }
        }

        if (forwardingParameters->forwardingPolicy.presence) {
            updkForwardingParameters->flags.forwardingPolicy = 1;
            uint8_t *forwardingPolicy = forwardingParameters->forwardingPolicy.value;
            UPDK_ForwardingPolicy *updkForwardingPolicy = &updkForwardingParameters->forwardingPolicy;

            updkForwardingPolicy->forwardingPolicyIdentifierLength = forwardingPolicy[0];
            UTLT_Assert(forwardingPolicy[0] < sizeof(updkForwardingPolicy->forwardingPolicyIdentifier), return STATUS_ERROR,
                "Forwarding Policy Identifier is too long");
            memcpy(updkForwardingPolicy->forwardingPolicyIdentifier, &forwardingPolicy[1], forwardingPolicy[0]);
            updkForwardingPolicy->forwardingPolicyIdentifier[forwardingPolicy[0]] = 0;
        }
    }

    return STATUS_OK;
}

Status UpfN4HandleUpdateFar(UpfSession *session, UpdateFAR *updateFar) {
    UTLT_Debug("Handle Update FAR");

    UTLT_Assert(updateFar->fARID.presence,
                return STATUS_ERROR, "Far ID not presence");

    UpfFAR upfFar;
    memset(&upfFar, 0, sizeof(UpfFAR));

    uint32_t farID = ntohl(*((uint32_t *)updateFar->fARID.value));
    UTLT_Assert(!UpfFARFindByID(farID, &upfFar), return STATUS_ERROR, "FAR ID[%u] does NOT exist in UPF Context", farID);

    UTLT_Assert(_ConvertUpdateFARTlvToRule(&upfFar, updateFar) == STATUS_OK,
        return STATUS_ERROR, "Convert FAR TLV To Rule is failed");

    // Get old apply action to check its changing
    uint8_t oldAction;
    UTLT_Assert(HowToHandleThisPacket(farID, &oldAction) == STATUS_OK, return STATUS_ERROR, "Can NOT find origin FAR action");

    // Using UPDK API
    UTLT_Assert(Gtpv1TunnelUpdateFAR(&upfFar) == 0, return STATUS_ERROR,
        "Gtpv1TunnelUpdateFAR failed");

    // Register FAR to Session
    UTLT_Assert(UpfFARRegisterToSession(session, &upfFar),
        return STATUS_ERROR, "UpfFARRegisterToSession failed");

    // Buffered packet handle
    if ((oldAction & PFCP_FAR_APPLY_ACTION_BUFF)) {
        Sock *sock = &Self()->upSock;

        UpfBufPacket *bufPacket;
        if (upfFar.applyAction & PFCP_FAR_APPLY_ACTION_DROP) {
            UpfPDRNode *node, *nextNode = NULL;
            ListForEachSafe(node, nextNode, &session->pdrList) {
                UTLT_Assert((bufPacket = UpfBufPacketFindByPdrId(node->pdr.pdrId)), continue, "");
                UpfBufPacketRemove(bufPacket);
            }
        } else if (upfFar.applyAction & PFCP_FAR_APPLY_ACTION_FORW) {
            sock->remoteAddr._family = sock->localAddr._family;
            sock->remoteAddr._port = sock->localAddr._port;
            
            if (sock->localAddr._family == AF_INET)
                sock->remoteAddr.s4.sin_addr = upfFar.forwardingParameters.outerHeaderCreation.ipv4;
            else
                UTLT_Warning("Do NOT support IPv6 yet");
            
            UpfPDRNode *node, *nextNode = NULL;
            ListForEachSafe(node, nextNode, &session->pdrList) {
                UTLT_Assert(UpSendPacketByPdrFar(&node->pdr, &upfFar, sock) == STATUS_OK,
                    continue, "UpSendPacketByPdrFar failed: PDR ID[%u], FAR ID[%u]", node->pdr.pdrId, node->pdr.farId);
            }
        }
    }

    // Validate the SRR state machine's state and release the resource of SRR
    if (oldAction & PFCP_FAR_APPLY_ACTION_NOCP && !(upfFar.applyAction & PFCP_FAR_APPLY_ACTION_NOCP)) {
        UpfPDRNode *node, *nextNode = NULL;
        uint16_t pdr_id = 0;
        
        ListForEachSafe(node, nextNode, &session->pdrList) {
            if (node->pdr.farId == upfFar.farId) {
                pdr_id = node->pdr.pdrId; 
                break;
            }
        }
        if (pdr_id) {
            UpfSRRNode *srr = UpfSrrFindByPdrId(session, pdr_id);
            if (srr) {
               UpfSrrRemoveNode(srr); 
            }
        }
    }

    return STATUS_OK;
}

Status _ConvertUpdateQERTlvToRule(UpfQER *upfQer, UpdateQER *updateQer) {
    UTLT_Assert(upfQer && updateQer, return STATUS_ERROR,
        "UpfQER or UpdateQER pointer should not be NULL");

    int offset;

// UpdateQER is same as CreateQER, so these are copied from _ConvertCreateQERTlvToRule
    if (updateQer->qERID.presence) {
        upfQer->flags.qerId = 1;
        upfQer->qerId = ntohl(*((uint32_t *) updateQer->qERID.value));
        UTLT_Debug("QER ID: %u", QERGetID(upfQer));
    }

    if (updateQer->qERCorrelationID.presence) {
        upfQer->flags.qerCorrelationId = 1;
        upfQer->qerCorrelationId = ntohl(*((uint32_t *) updateQer->qERCorrelationID.value));
        UTLT_Debug("QER Correlation ID value: %u", QERGetCorrelationID(upfQer));
    }

    if (updateQer->gateStatus.presence) {
        upfQer->flags.gateStatus = 1;
        upfQer->gateStatus = *((uint8_t *) updateQer->gateStatus.value);
        UTLT_Debug("QER Gate Status: %u", QERGetGateStatus(upfQer));
    }

    if (updateQer->maximumBitrate.presence) {
        upfQer->flags.maximumBitrate = 1;
        Pfcp5ByteBitRateToHost(updateQer->maximumBitrate.value, &upfQer->maximumBitrate.ul);
        Pfcp5ByteBitRateToHost(updateQer->maximumBitrate.value + sizeof(uint8_t) * 5, &upfQer->maximumBitrate.dl);
        UTLT_Debug("QER MBR UL: %u, DL: %u", QERGetMBRUL(upfQer), QERGetMBRDL(upfQer));
    }

    if (updateQer->guaranteedBitrate.presence) {
        upfQer->flags.guaranteedBitrate = 1;
        Pfcp5ByteBitRateToHost(updateQer->guaranteedBitrate.value, &upfQer->guaranteedBitrate.ul);
        Pfcp5ByteBitRateToHost(updateQer->guaranteedBitrate.value + sizeof(uint8_t) * 5, &upfQer->guaranteedBitrate.dl);
        UTLT_Debug("QER GBR UL: %u, DL: %u", QERGetGBRUL(upfQer), QERGetGBRDL(upfQer));
    }

    if (updateQer->packetRate.presence) {
        upfQer->flags.packetRate = 1;
        memcpy(&upfQer->packetRate.flags, updateQer->packetRate.value, sizeof(uint8_t));
        UTLT_Debug("QER Packet Rate flags ulpr: %u, dlpr : %u",
                QERGetPacketRate(upfQer).flags.ulpr, QERGetPacketRate(upfQer).flags.dlpr);
        offset = sizeof(uint8_t);
        
        if (QERGetPacketRate(upfQer).flags.ulpr) {
            upfQer->packetRate.uplinkTimeUnit = *((uint8_t *) (updateQer->packetRate.value + offset));
            upfQer->packetRate.maximumUplinkPacketRate = ntohs(*((uint16_t *) (updateQer->packetRate.value + offset + 1)));
            UTLT_Debug("QER Packet Rate Uplink Time Unit: %u, Maximum Uplink Packet Rate: %u",
                    QERGetPacketRateULTimeUnit(upfQer), QERGetPacketRateMaxUL(upfQer));
            offset += 3;
        }

        if (QERGetPacketRate(upfQer).flags.dlpr) {
            upfQer->packetRate.downlinkTimeUnit = *((uint8_t *) (updateQer->packetRate.value + offset));
            upfQer->packetRate.maximumDownlinkPacketRate = ntohs(*((uint16_t *) (updateQer->packetRate.value + offset + 1)));
            UTLT_Debug("QER Packet Rate Downlink Time Unit: %u, Maximum Downlink Packet Rate: %u",
                    QERGetPacketRateDLTimeUnit(upfQer), QERGetPacketRateMaxDL(upfQer));
            // offset += 3;
        }
    }

    if (updateQer->dLFlowLevelMarking.presence) {
        upfQer->flags.dlFlowLevelMarking = 1;
        memcpy(&upfQer->dlFlowLevelMarking.flags, updateQer->dLFlowLevelMarking.value, sizeof(uint8_t));
        UTLT_Debug("QER DL Flow Level Marking flags TTC: %u, SCI: %u",
                QERGetDLFlowLevelMark(upfQer).flags.ttc, QERGetDLFlowLevelMark(upfQer).flags.sci);
        offset = sizeof(uint8_t);

        if (QERGetDLFlowLevelMark(upfQer).flags.ttc) {
            // TS 29.244 8.2.66 The ToS/Traffic Class field, when present, shall be encoded on two octets as an OctetString
            upfQer->dlFlowLevelMarking.tosTrafficClass = *((uint16_t *) (updateQer->dLFlowLevelMarking.value + offset));
            UTLT_Debug("QER DL Flow Level Marking ToS/Traffic Class: %u",
                    QERGetDLFlowLevelMarkTTC(upfQer));
            offset += sizeof(uint16_t);
        }

        if (QERGetDLFlowLevelMark(upfQer).flags.sci) {
            upfQer->dlFlowLevelMarking.serviceClassIndicator = *((uint16_t *) (updateQer->dLFlowLevelMarking.value + offset));
            UTLT_Debug("QER DL Flow Level Marking Service Class Indicator: %u",
                    QERGetDLFlowLevelMarkSCI(upfQer));
            // offset += sizeof(uint16_t);
        }
    }

    if (updateQer->qoSFlowIdentifier.presence) {
        upfQer->flags.qosFlowIdentifier = 1;
        upfQer->qosFlowIdentifier = *((uint8_t *) (updateQer->qoSFlowIdentifier.value));
        UTLT_Debug("QER QoS Flow Identifier: %u", QERGetQFI(upfQer));
    }

    if (updateQer->reflectiveQoS.presence) {
        upfQer->flags.reflectiveQos = 1;
        upfQer->reflectiveQos = *((uint8_t *) (updateQer->reflectiveQoS.value));
        UTLT_Debug("QER Reflective QoS: %u", QERGetRQI(upfQer));
    }

    return STATUS_OK;
}

Status UpfN4HandleUpdateQer(UpfSession *session, UpdateQER *updateQer) {
    UTLT_Debug("Handle Update QER");

    UTLT_Assert(updateQer->qERID.presence,
                return STATUS_ERROR, "Qer ID not presence");

    UpfQER upfQer;
    memset(&upfQer, 0, sizeof(UpfQER));

    uint32_t qerID = ntohl(*((uint32_t *)updateQer->qERID.value));
    UTLT_Assert(!UpfQERFindByID(qerID, &upfQer), return STATUS_ERROR, "QER ID[%u] does NOT exist in UPF Context", qerID);

    UTLT_Assert(_ConvertUpdateQERTlvToRule(&upfQer, updateQer) == STATUS_OK,
        return STATUS_ERROR, "Convert Update QER TLV To Rule is failed");

    // Using UPDK API
    UTLT_Assert(Gtpv1TunnelUpdateQER(&upfQer) == 0, return STATUS_ERROR,
        "Gtpv1TunnelUpdateQER failed");

    // Register QER to Session
    UTLT_Assert(UpfQERRegisterToSession(session, &upfQer),
        return STATUS_ERROR, "UpfQERRegisterToSession failed");

    return STATUS_OK;
}

Status _ConvertRemovePDRTlvToRule(UpfPDR *upfPdr, uint16_t nPDRID) {
    // TODO: Need to Find the PDR stored in UPF
    upfPdr->flags.pdrId = 1;
    upfPdr->pdrId = ntohs(nPDRID);

    return STATUS_OK;
}

Status UpfN4HandleRemovePdr(UpfSession *session, uint16_t nPDRID) {
    uint16_t pdrID = ntohs(nPDRID);

    UTLT_Debug("Handle Remove PDR[%u]", pdrID);
    UTLT_Assert(pdrID, return STATUS_ERROR, "PDR ID cannot be 0");
    UTLT_Assert(session, return STATUS_ERROR,
                "session not found");

    UpfPDR upfPdr;
    memset(&upfPdr, 0, sizeof(UpfPDR));

    UTLT_Assert(!UpfPDRFindByID(pdrID, &upfPdr), return STATUS_ERROR, "PDR ID[%u] does NOT exist in UPF Context", pdrID);    

    UTLT_Assert(_ConvertRemovePDRTlvToRule(&upfPdr, nPDRID) == STATUS_OK,
            return STATUS_ERROR, "Convert PDR TLV To Rule is failed");

    // Using UPDK API
    UTLT_Assert(Gtpv1TunnelRemovePDR(&upfPdr) == 0, return STATUS_ERROR,
        "Gtpv1TunnelRemovePDR failed");
    
    // Remove Buffering packet
    UpfBufPacket *packetStorage = UpfBufPacketFindByPdrId(pdrID);
    if (packetStorage)
        UpfBufPacketRemove(packetStorage);

    UpfSRRNode *srr = UpfSrrFindByPdrId(session, pdrID);
    if (srr != NULL) {
        //Don't change the state of SRR
        UpfSrrRemoveNode(srr);
    }

    // Deregister PDR to Session
    UTLT_Assert(UpfPDRDeregisterToSessionByID(session, upfPdr.pdrId) == STATUS_OK,
        return STATUS_ERROR, "UpfPDRDeregisterToSessionByID failed");

    return STATUS_OK;
}

Status _ConvertRemoveFARTlvToRule(UpfFAR *upfFar, uint32_t nFARID) {
    // TODO: Need to Find the FAR stored in UPF
    upfFar->flags.farId = 1;
    upfFar->farId = ntohl(nFARID);

    return STATUS_OK;
}

Status UpfN4HandleRemoveFar(UpfSession *session, uint32_t nFARID) {
    uint32_t farID = ntohl(nFARID);

    UTLT_Debug("Handle Remove FAR[%u]", farID);
    UTLT_Assert(farID, return STATUS_ERROR,
                "farId should not be 0");

    UpfFAR upfFar;
    memset(&upfFar, 0, sizeof(UpfFAR));

    UTLT_Assert(!UpfFARFindByID(farID, &upfFar), return STATUS_ERROR, "FAR ID[%u] does NOT exist in UPF Context", farID);

    UTLT_Assert(_ConvertRemoveFARTlvToRule(&upfFar, nFARID) == STATUS_OK,
        return STATUS_ERROR, "Convert FAR TLV To Rule is failed");

    // Using UPDK API
    UTLT_Assert(Gtpv1TunnelRemoveFAR(&upfFar) == 0, return STATUS_ERROR,
        "Gtpv1TunnelRemovefar failed");

    // Deregister FAR to Session
    UTLT_Assert(UpfFARDeregisterToSessionByID(session, upfFar.farId) == STATUS_OK,
        return STATUS_ERROR, "UpfFARDeregisterToSessionByID failed");

    return STATUS_OK;
}

Status _ConvertRemoveQERTlvToRule(UpfQER *upfQer, uint32_t nQERID) {
    // TODO: Need to Find the QER stored in UPF
    upfQer->flags.qerId = 1;
    upfQer->qerId = ntohl(nQERID);

    return STATUS_OK;
}

Status UpfN4HandleRemoveQer(UpfSession *session, uint32_t nQERID) {
    uint32_t qerID = ntohl(nQERID);

    UTLT_Debug("Handle Remove QER[%u]", qerID);
    UTLT_Assert(qerID, return STATUS_ERROR,
                "qerId should not be 0");

    UpfQER upfQer;
    memset(&upfQer, 0, sizeof(UpfQER));

    UTLT_Assert(!UpfQERFindByID(qerID, &upfQer), return STATUS_ERROR, "QER ID[%u] does NOT exist in UPF Context", qerID);

    UTLT_Assert(_ConvertRemoveQERTlvToRule(&upfQer, nQERID) == STATUS_OK,
        return STATUS_ERROR, "Convert Remove QER TLV To Rule is failed");

    // Using UPDK API
    UTLT_Assert(Gtpv1TunnelRemoveQER(&upfQer) == 0, return STATUS_ERROR,
        "Gtpv1TunnelRemoveqer failed");

    // Deregister QER to Session
    UTLT_Assert(UpfQERDeregisterToSessionByID(session, upfQer.qerId) == STATUS_OK,
        return STATUS_ERROR, "UpfQERDeregisterToSessionByID failed");

    return STATUS_OK;
}

/* TODO: PFCP Session Establishment Request may have one or more PDRs, 
 * FARs, QERs, ...
 * Current implmentation supports only FOUR PDRs, FARs, and QERs
 * 
 *	The order of PDRs, FARs, and QERs like below (sample flow)
 *		1) FARs  	(order MAY change)
 *		2) QERs		(order MAY change)
 *		3) PDRs 	(Final SHOULD NOT change)
 */
Status UpfN4HandleSessionEstablishmentRequest(UpfSession *session, PfcpXact *pfcpXact,
    PfcpHeader *reqHdr, PFCPSessionEstablishmentRequest *request) {
    Status status;
    uint8_t cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    PfcpHeader header;
    Bufblk *bufBlk = NULL;
    uint32_t sqn;
    uint16_t state;

    UTLT_Assert(session, return STATUS_ERROR, "SessEstReq: session NULL");
    UTLT_Assert(pfcpXact, return STATUS_ERROR, "SessEstReq: Xact NULL");

    sqn = GetPfcpRequestSqn(reqHdr);    
    state = ValidateUpfSessionState(session, 
        PFCP_SESSION_ESTABLISHMENT_REQUEST, 
        sqn);
    if (state == REQUEST_DROP) {
        goto out;
    } else if (state == REQUEST_RESPONSE) {
        /* TODO: Validate the received packet with existing values of PDR, FAR, QER */
        goto send_rsp;
    }
    
    for (int i = 0; i < sizeof(request->createFAR) / sizeof(CreateFAR); i++) {
        if (request->createFAR[i].presence) {
            status = UpfN4HandleCreateFar(session, &request->createFAR[i]);
            // TODO: if error, which cause, and pull out the rule from kernel that
            // has been set, maybe need to pull out session as well
            UTLT_Assert(status == STATUS_OK, cause = PFCP_CAUSE_REQUEST_REJECTED,
                "SessEstReq: Create FAR error ST: %d", status);
        }
    }

	/* QER: TODO, Currently we support 4QER's per request, and also 
     * we send only one QER info to gtp5g
     * */
    for (int i = 0; i < sizeof(request->createQER) / sizeof(CreateQER); i++) {
        if (request->createQER[i].presence) {
            status = UpfN4HandleCreateQer(session, &request->createQER[i]);
            // TODO: if error, which cause, and pull out the rule from kernel that
            // has been set, maybe need to pull out session as well
            UTLT_Assert(status == STATUS_OK, cause = PFCP_CAUSE_REQUEST_REJECTED,
                "SessEstReq: Create QER error ST: %d", status);
        }
    }

    if (request->createURR.presence) {
        // TODO
        UTLT_Warning("SessEstReq:: CreateURR unhandled");
    }

    if (request->createBAR.presence) {
        // TODO
        UTLT_Warning("SessEstReq:: CreateBAR unhandled");
    }

    // The order of PDR should be the lastest one
    for (int i = 0; i < sizeof(request->createPDR) / sizeof(CreatePDR); i++) {
        if (request->createPDR[i].presence) {
            status = UpfN4HandleCreatePdr(session, &request->createPDR[i]);
            UTLT_Assert(status == STATUS_OK, cause = PFCP_CAUSE_REQUEST_REJECTED,
                "SessEstReq: Create PDR error ST: %d", status);
        }
    }

    if (!request->cPFSEID.presence) {
        UTLT_Error("SessEstReq:: No CP F-SEID");
        cause = PFCP_CAUSE_MANDATORY_IE_MISSING;
    }

    UpdateUpfSessionState(session, 
        PFCP_SESSION_ESTABLISHMENT_REQUEST, 
        SMF_UPF_SESSION_STATE_HANDLE, 
        SMF_UPF_SESSION_SUB_STATE_HANDLE_SUCCESS);

send_rsp:
    /* Send Response */
    memset(&header, 0, sizeof(PfcpHeader));
    header.type = PFCP_SESSION_ESTABLISHMENT_RESPONSE;
    header.seid = session->smfSeid;

    status = UpfN4BuildSessionEstablishmentResponse(&bufBlk, 
        header.type,
        session, 
        cause, 
        request);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
        "SessEstReq: N4 build  ST: %d", status);

    status = PfcpXactUpdateTx(pfcpXact, &header, bufBlk);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
        "SessEstReq: pfcpXact update TX  ST: %d", status);

    status = PfcpXactCommit(pfcpXact);
    if (status != STATUS_OK) {
        UpdateUpfSessionState(session, 
            PFCP_SESSION_ESTABLISHMENT_REQUEST, 
            SMF_UPF_SESSION_STATE_SEND_RSP, 
            SMF_UPF_SESSION_SUB_STATE_SEND_RSP_FAILURE);
        UTLT_Error("SessEstReq: Failed to xact commit error ST: %d", status);
    }

    UpdateUpfSessionState(session, 
        PFCP_SESSION_ESTABLISHMENT_REQUEST, 
        SMF_UPF_SESSION_STATE_SEND_RSP, 
        SMF_UPF_SESSION_SUB_STATE_SEND_RSP_SUCCESS);

    UTLT_Debug("SessEstReq: Session Establishment Request done");
out:
    return STATUS_OK;
}

Status UpfN4HandleSessionModificationRequest(UpfSession *session, PfcpXact *xact,
    PFCPSessionModificationRequest *request) {
    UTLT_Assert(session, return STATUS_ERROR, "SessMod: Session NULL");
    UTLT_Assert(xact, return STATUS_ERROR, "SessMod: xact NULL");

    Status status;
    PfcpHeader header;
    Bufblk *bufBlk;

    /* Create FAR */
    for (int i = 0; i < sizeof(request->createFAR) / sizeof(CreateFAR); i++) {
        if (request->createFAR[i].presence) {
            status = UpfN4HandleCreateFar(session, &request->createFAR[i]);
            UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "SessMod: Create FAR error ST: %d", status);
        }
    }

    /* Create QER */
    for (int i = 0; i < sizeof(request->createQER) / sizeof(CreateQER); i++) {
        if (request->createQER[i].presence) {
            status = UpfN4HandleCreateQer(session, &request->createQER[i]);
            UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "SessMod: Create QER error ST: %d", status);
        }
    }

    // The order of PDF should be the lastest
    /* Create PDR */
    for (int i = 0; i < sizeof(request->createPDR) / sizeof(CreatePDR); i++) {
        if (request->createPDR[i].presence) {
            status = UpfN4HandleCreatePdr(session, &request->createPDR[i]);
            UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "SessMod: Create PDR error ST: %d", status);
        }
    }

    /* Update FAR */
    for (int i = 0; i < sizeof(request->updateFAR) / sizeof(UpdateFAR); i++) {
        if (request->updateFAR[i].presence) {
            UTLT_Assert(request->updateFAR[i].fARID.presence == 1, ,
                "SessMod: UpdateFAR farID not presence");
            status = UpfN4HandleUpdateFar(session, &request->updateFAR[i]);
            UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "SessMod: Update FAR error ST: %d", status);
        }
    }

    /* Update QER */
    for (int i = 0; i < sizeof(request->updateQER) / sizeof(UpdateQER); i++) {
        if (request->updateQER[i].presence) {
            UTLT_Assert(request->updateQER[i].qERID.presence == 1, ,
                "SessMod: UpdateQER QerId not presence");
            status = UpfN4HandleUpdateQer(session, &request->updateQER[i]);
            UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "SessMod:: UpdateQER error ST: %d", status);
        }
    }

    // The order of PDF should be the lastest
    /* Update PDR */
    for (int i = 0; i < sizeof(request->updatePDR) / sizeof(UpdatePDR); i++) {
        if (request->updatePDR[i].presence) {
            UTLT_Assert(request->updatePDR[i].pDRID.presence == 1, ,
                "SessMod: UpdatePDR PdrID not presence");
            status = UpfN4HandleUpdatePdr(session, &request->updatePDR[i]);
            UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "SessMod:: UpdatePDR error ST: %d", status);
        }
    }

    /* Remove FAR */
    for (int i = 0; i < sizeof(request->removeFAR) / sizeof(RemoveFAR); i++) {
        if (request->removeFAR[i].presence) {
            UTLT_Assert(request->removeFAR[i].fARID.presence == 1, ,
                "SessMod: RemoveFAR farID not presence");
            status = UpfN4HandleRemoveFar(session, 
                *(uint32_t *) request->removeFAR[i].fARID.value);
            UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "SessMod: RemoveFAR error ST: %d", status);
        }
    }

    /* Remove QER */
    for (int i = 0; i < sizeof(request->removeQER) / sizeof(RemoveQER); i++) {
        if (request->removeQER[i].presence) {
            UTLT_Assert(request->removeQER[i].qERID.presence == 1, ,
                "SessMod: RemoveQER QerId not presence");
            status = UpfN4HandleRemoveQer(session, 
                *(uint32_t *) request->removeQER[i].qERID.value);
            UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "SessMod: RemoveQER error ST: %d", status);
        }
    }

    // The order of PDF should be the lastest
    /* Remove PDR */
    for (int i = 0; i < sizeof(request->removePDR) / sizeof(RemovePDR); i++) {
        if (request->removePDR[i].presence) {
            UTLT_Assert(request->removePDR[i].pDRID.presence == 1, ,
                "SessMod: RemovePDR pdrId not presence!");
            status = UpfN4HandleRemovePdr(session, 
                *(uint16_t *) request->removePDR[i].pDRID.value);
            UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "SessMod: RemovePDR error ST: %d", status);
        }
    }

    /* Send Session Modification Response */
    memset(&header, 0, sizeof(PfcpHeader));
    header.type = PFCP_SESSION_MODIFICATION_RESPONSE;
    header.seid = session->smfSeid;

    status = UpfN4BuildSessionModificationResponse(&bufBlk, 
        header.type,
        session, 
        request);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
        "SessMod: Response build error ST: %d", status);

    status = PfcpXactUpdateTx(xact, &header, bufBlk);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
        "SessMod: PfcpXactUpdateTx error ST: %d", status);

    status = PfcpXactCommit(xact);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
        "SessMod: PFCP Xact Commit error ST: %d", status);

    UTLT_Debug("SessMod: Session Modification Request Done");
    return STATUS_OK;
}

Status UpfN4HandleSessionDeletionRequest(UpfSession *session, PfcpXact *xact,
    PFCPSessionDeletionRequest *request) {
    
    UTLT_Assert(session, return STATUS_ERROR, "SessDel: session NULL");
    UTLT_Assert(xact, return STATUS_ERROR, "SessDel: xact NULL");

    Status status;
    PfcpHeader header;
    Bufblk *bufBlk = NULL;

    //TODO: Validate the current and given values
 
    UTLT_Assert(UpfSessionRemove(session) == STATUS_OK, return STATUS_ERROR,
        "SessDel: UpfSessionRemove failed");

    /* Send Session Deletion Response */
    memset(&header, 0, sizeof(PfcpHeader));
    header.type = PFCP_SESSION_DELETION_RESPONSE;
    header.seid = session->smfSeid;

    status = UpfN4BuildSessionDeletionResponse(&bufBlk,
        header.type,
        session, 
        request);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, 
        "SessDel: Response build error ST: %d", status);

    status = PfcpXactUpdateTx(xact, &header, bufBlk);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
        "SessDel: PfcpXactUpdateTx error ST: %d", status);

    status = PfcpXactCommit(xact);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, 
        "SessDel: xact commit error ST: %d", status);

    UTLT_Debug("SessDel: Session Deletion Request done");
    return STATUS_OK;
}

Status UpfN4HandleSessionReportResponse(UpfSession *session, PfcpXact *xact,
    uint32_t seqId, PFCPSessionReportResponse *response) {
    Status status;

    UTLT_Assert(session, return STATUS_ERROR, "SRR: Session NULL");
    UTLT_Assert(xact, return STATUS_ERROR, "SRR: xact NULL");
    UTLT_Assert(response->cause.presence, return STATUS_ERROR,
        "SRR: Cause not present");

    // TODO: check if need update TX
    UpfSRRNode *srr = UpfSrrFindBySeqId(session, seqId);
    if (srr != NULL) {
        srr->state = SRR_STATE_RECV;
        //The timer will be stopped in timer handler of SRR 
    } else {
        UTLT_Error("SRR: Can't find SRR Node by SeqId(%#x)", seqId);
    }

    status = PfcpXactCommit(xact);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "SRR: xact commit error ST: %d", status);
    struct timeval  tv;
    gettimeofday(&tv, NULL);
    UTLT_Info("SRR: Session Report Request done: %f (sec)", (float)(tv.tv_usec)/1000000);
    return STATUS_OK;
}

Status UpfN4HandleAssociationSetupRequest(PfcpXact *xact,
    PFCPAssociationSetupRequest *request) {
    PfcpNodeId *nodeId;

    UTLT_Assert(xact, return STATUS_ERROR, "AssSetupReq: xact NULL");
    UTLT_Assert(xact->gnode, return STATUS_ERROR, "AssSetupReq: gNode NULL");
    UTLT_Assert(request->nodeID.presence, return STATUS_ERROR,
        "AssSetupReq: NodeId is not present");

    nodeId = (PfcpNodeId *) request->nodeID.value;

    /* gnode object allocated or referenced in function 
     * _pfcpReceiveCB
     * */
    xact->gnode->nodeId.type = nodeId->type;
    switch (nodeId->type) {
    case PFCP_NODE_ID_IPV4:
        xact->gnode->nodeId.addr4 = nodeId->addr4;
        break;
    case PFCP_NODE_ID_IPV6:
        xact->gnode->nodeId.addr6 = nodeId->addr6;
        break;
    case PFCP_NODE_ID_FQDN :
        memcpy(xact->gnode->nodeId.fqdn, nodeId->fqdn, sizeof(nodeId->fqdn));
        break;
    default:
        UTLT_Assert(0, return STATUS_ERROR, "AssSetupReq: Request don't have node id type");
        break;
    }

    xact->gnode->state = PFCP_NODE_ST_ASSOCIATED;

    Status status;
    PfcpHeader header;
    Bufblk *bufBlk = NULL;

    memset(&header, 0, sizeof(PfcpHeader));
    header.type = PFCP_ASSOCIATION_SETUP_RESPONSE;
    header.seid = 0;
    status = UpfN4BuildAssociationSetupResponse(&bufBlk, header.type);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
        "AssSetupReq: N4 build error ST: %d", status);

    status = PfcpXactUpdateTx(xact, &header, bufBlk);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
        "AssSetupReq: Xact Update Tx error ST: %d", status);

    status = PfcpXactCommit(xact);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
        "AssSetupReq: xact commit error ST: %d", status);

    UTLT_Debug("AssSetupReq: Association Setup Request done");
    return STATUS_OK;
}

Status UpfN4HandleAssociationUpdateRequest(PfcpXact *xact,
    PFCPAssociationUpdateRequest *request) {
    // TODO
    UTLT_Error("AssUpReq: TODO Association Update Request");
    return STATUS_OK;
}

Status UpfN4HandleAssociationReleaseRequest(PfcpXact *xact,
    PFCPAssociationReleaseRequest *request) {
    UTLT_Assert(xact, return STATUS_ERROR, "AssRel: xact NULL");
    UTLT_Assert(xact->gnode, return STATUS_ERROR,
        "AssRel: gNode of xact NULL");
    UTLT_Assert(request->nodeID.presence, return STATUS_ERROR,
        "AssRel: missing nodeId");

    // Clear all session releated to this node
    HashIndex *sessionHashIdx = NULL;
    UpfSession *session = NULL;
    for (sessionHashIdx = UpfSessionFirst(); sessionHashIdx;
        sessionHashIdx = UpfSessionNext(sessionHashIdx)) {
        session = UpfSessionThis(sessionHashIdx);
        // Clear transaction node
        if (session->pfcpNode == xact->gnode) {
            UpfSessionRemove(session);
        }
    }

    // TODO: Delete the Node (which was created by _pfcpReceiveCB) and release outstanding xactin except the
    // current one

    // Build Response
    Status status;
    PfcpHeader header;
    Bufblk *bufBlk = NULL;

    memset(&header, 0, sizeof(PfcpHeader));
    header.type = PFCP_ASSOCIATION_RELEASE_RESPONSE;
    header.seid = 0;

    status = UpfN4BuildAssociationReleaseResponse(&bufBlk, header.type);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
        "AssRel: Response build error ST: %d", status);

    status = PfcpXactUpdateTx(xact, &header, bufBlk);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
        "AssRel: PfcpXactUpdateTx error ST: %d", status);

    status = PfcpXactCommit(xact);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
        "AssRel: xact commit error ST: %d", status);

    UTLT_Info("AssRel: Association Release Request done");
    return STATUS_OK;
}

Status UpfN4HandleHeartbeatRequest(PfcpXact *xact, HeartbeatRequest *request) {
    Status status;
    PfcpHeader header;
    Bufblk *bufBlk = NULL;

    UTLT_Assert(xact, return STATUS_ERROR, "HeartReq: xact NULL");

    /* Send */
    memset(&header, 0, sizeof(PfcpHeader));
    header.type = PFCP_HEARTBEAT_RESPONSE;
    header.seid = 0;

    status = UpfN4BuildHeartbeatResponse(&bufBlk, header.type);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
        "HeartReq: Response build error ST: %d", status);

    status = PfcpXactUpdateTx(xact, &header, bufBlk);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
        "HeartReq: PfcpXactUpdateTx error ST: %d", status);

    status = PfcpXactCommit(xact);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
        "HeartReq: xact commit error ST: %d", status);

    UTLT_Info("HeartReq: Heartbeat Request done");
    return STATUS_OK;
}

Status UpfN4HandleHeartbeatResponse(PfcpXact *xact,
                                    HeartbeatResponse *response) {
    // if rsv response, nothing to do, else peer may be not alive
    UTLT_Error("HeartRsp: TODO ");
    return STATUS_OK;
}
