#include "updk/rule.h"

#include "utlt_debug.h"
#include "libgtp5gnl/gtp5g.h"
#include "libgtp5gnl/gtp5gnl.h"
#include "gtp_tunnel.h"

#include "gtp5g_context.h"
#include "updk/rule_qer.h"

/*
 * These functions shall be customized by kinds of device.
 * You can create a directory and put all customized function
 * in there, like "device.c" under "updk/src/kernel/include"
 *
 * Note:
 * 1. Parameter in each Gtpv1Tunnel* function may not be the same.
 * Therefore, please do not use memory copy function to handle in different type.
 * 2. Function "Gtpv1Tunnel*" how to work is dependent on the kind of device.
 * It is up to you can set the real rule into your device or just treat it
 * as a notification.
 */

typedef struct gtp5g_qer     UpfQer;

enum {
    RULE_QER_UNSPEC = 0,

    RULE_QER_ADD,
    RULE_QER_MOD,
    RULE_QER_DEL,

    RULE_QER_MAX,
};

Status _pushQerToKernel(struct gtp5g_qer *qer, int action) {
    UTLT_Assert(qer, return -1, "push QER not found");
    Status status;

    // Only support single device in our UPF
    char *ifname = Gtp5gSelf()->ifname;
    uint32_t qerId = *(uint32_t*)gtp5g_qer_get_id(qer);

	switch (action) {
    case RULE_QER_ADD:
        UTLT_Debug("QER add to kernel, dev: %s, qer id: %u",
                   ifname, ntohl(qerId));
        status = GtpTunnelAddQer(ifname, qer);
        UTLT_Assert(status == STATUS_OK, return -1, "Add QER failed");
        break;
    case RULE_QER_MOD:
        UTLT_Debug("QER modify to kernel, dev: %s, qer id: %u",
                   ifname, ntohl(qerId));
        status = GtpTunnelModQer(ifname, qer);
        UTLT_Assert(status == STATUS_OK, return -1, "Modify QER failed");
        break;
    case RULE_QER_DEL:
        UTLT_Debug("QER delete to kernel, dev: %s, qer id: %u",
                   ifname, ntohl(qerId));
        status = GtpTunnelDelQer(ifname, qerId);
        UTLT_Assert(status == STATUS_OK, return -1, "Delete QER failed");
        break;
    default:
        UTLT_Assert(0, return -1, "QER Action %d not defined", action);
    }

    return STATUS_OK;
}

int _SetGtp5gQer(UpfQer *upfQer, UPDK_QER *qer) {
    gtp5g_qer_set_id(upfQer, qer->qerId);
    UTLT_Debug("gtp5g get QER ID: %u", qer->qerId);
	
	if (qer->flags.qerCorrelationId) {
        UTLT_Debug("gtp5g QER CorrelationID: %u", qer->qerCorrelationId);
		gtp5g_qer_set_qer_corr_id(upfQer, qer->qerCorrelationId);
	}
	
	if (qer->flags.gateStatus) {
        UTLT_Debug("gtp5g QER ULDL gate status: %u", qer->gateStatus);
		gtp5g_qer_set_gate_status(upfQer, qer->gateStatus);
	}
	
	if (qer->flags.maximumBitrate) {
        UTLT_Debug("gtp5g QER MBR UL: %u", qer->maximumBitrate.ul);
        UTLT_Debug("gtp5g QER MBR DL: %u", qer->maximumBitrate.dl);
		gtp5g_qer_set_mbr_uhigh(upfQer, (uint32_t)(qer->maximumBitrate.ul >> 8));
		gtp5g_qer_set_mbr_ulow(upfQer, (uint8_t)qer->maximumBitrate.ul);
		gtp5g_qer_set_mbr_dhigh(upfQer, (uint32_t)(qer->maximumBitrate.dl >> 8));
		gtp5g_qer_set_mbr_dlow(upfQer, (uint8_t)qer->maximumBitrate.dl);
	}
	
	if (qer->flags.guaranteedBitrate) {
        UTLT_Debug("gtp5g QER GBR UL: %u", qer->guaranteedBitrate.ul);
        UTLT_Debug("gtp5g QER GBR DL: %u", qer->guaranteedBitrate.dl);
		gtp5g_qer_set_gbr_uhigh(upfQer, (uint32_t)(qer->guaranteedBitrate.ul >> 8));
		gtp5g_qer_set_gbr_ulow(upfQer, (uint8_t)qer->guaranteedBitrate.ul);
		gtp5g_qer_set_gbr_dhigh(upfQer, (uint8_t)(qer->guaranteedBitrate.dl >> 8));
		gtp5g_qer_set_gbr_dlow(upfQer, (uint32_t)qer->guaranteedBitrate.dl);
	}

	//TODO: packetRate
	
	//TODO: dlFlowLevelMarking
	
	if (qer->flags.qosFlowIdentifier) {
        UTLT_Debug("gtp5g QER QFI: %u", qer->qosFlowIdentifier);
		gtp5g_qer_set_qfi(upfQer, qer->qosFlowIdentifier);
	}
	
	if (qer->flags.reflectiveQos) {
        UTLT_Debug("gtp5g QER RQI: %u", qer->reflectiveQos);
		gtp5g_qer_set_rqi(upfQer, qer->reflectiveQos);
	}

	return 0;
}

int Gtpv1TunnelCreateQER(UPDK_QER *qer) {
    UTLT_Assert(qer, return -1, "UPDK_QER pointer is NULL");

    UTLT_Assert(qer->flags.qerId, return -1, "UPDK_QER ID is not set");

    Status status = STATUS_OK;

    UpfQer *tmpQer = gtp5g_qer_alloc();
    UTLT_Assert(tmpQer, return -1, "QER allocate error");

    status = _SetGtp5gQer(tmpQer, qer);
    UTLT_Assert(status == 0, goto freeqer, "Set gtp5g QER is failed");

    // Send QER to kernel
    status = _pushQerToKernel(tmpQer, RULE_QER_ADD);
    UTLT_Assert(status == STATUS_OK, goto freeqer, "QER not pushed to kernel");

freeqer:
    gtp5g_qer_free(tmpQer);
    UTLT_Assert(tmpQer != NULL, return -1, "Free QER struct error");
    return status;
}

int Gtpv1TunnelUpdateQER(UPDK_QER *qer) {
    UTLT_Assert(qer, return -1, "UPDK_QER pointer is NULL");

    UTLT_Assert(qer->flags.qerId, return -1, "UPDK_QER ID is not set");

    Status status = STATUS_OK;

    UpfQer *tmpQer = gtp5g_qer_alloc();
    UTLT_Assert(tmpQer, return -1, "QER allocate error");
    
    status = _SetGtp5gQer(tmpQer, qer);
    UTLT_Assert(status == 0, goto freeqer, "Set gtp5g QER is failed");

    // TODO: update QER to kernel
    status = _pushQerToKernel(tmpQer, RULE_QER_MOD);
    UTLT_Assert(status == STATUS_OK, goto freeqer, "QER not pushed to kernel");
    
freeqer:
    gtp5g_qer_free(tmpQer);
    UTLT_Assert(tmpQer != NULL, return -1, "Free QER struct error");
    return status;
}

int Gtpv1TunnelRemoveQER(UPDK_QER *qer) {
    UTLT_Assert(qer, return -1, "UPDK_QER pointer is NULL");

    UTLT_Assert(qer->flags.qerId, return -1, "UPDK_QER ID is not set");

    UTLT_Assert(GtpTunnelDelQer(Gtp5gSelf()->ifname, qer->qerId) == STATUS_OK,
        return -1, "QER[%u] delete failed", qer->qerId);

    return 0;
}
