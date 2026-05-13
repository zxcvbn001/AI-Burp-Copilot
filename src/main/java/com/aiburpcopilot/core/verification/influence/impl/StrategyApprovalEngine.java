package com.aiburpcopilot.core.verification.influence.impl;

import com.aiburpcopilot.core.verification.influence.IStrategyApprovalEngine;
import com.aiburpcopilot.core.verification.model.InfluenceResult;
import com.aiburpcopilot.core.verification.model.InfluenceStatus;
import com.aiburpcopilot.core.verification.model.ParameterProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StrategyApprovalEngine implements IStrategyApprovalEngine {

    private static final Logger log = LoggerFactory.getLogger(StrategyApprovalEngine.class);

    @Override
    public InfluenceResult approve(InfluenceResult result, ParameterProfile profile, double minScore) {
        if (result == null) {
            InfluenceResult r = new InfluenceResult();
            r.setApproved(false);
            r.setApprovalReason("Null influence result");
            return r;
        }

        // Check 1: Influence score
        if (result.getInfluenceScore() < minScore) {
            result.setApproved(false);
            result.setStatus(InfluenceStatus.NOT_INFLUENTIAL);
            result.setApprovalReason(String.format(
                    "Influence score too low: %.3f < %.3f", result.getInfluenceScore(), minScore));
            log.debug("Rejected: {}", result.getApprovalReason());
            return result;
        }

        // Check 2: Parameter mutability
        if (profile != null && !profile.isMutable()) {
            result.setApproved(false);
            result.setStatus(InfluenceStatus.NOT_INFLUENTIAL);
            result.setApprovalReason("Parameter is not mutable (type=" + profile.getDetectedType() + ")");
            log.debug("Rejected: {}", result.getApprovalReason());
            return result;
        }

        // Check 3: Replay success
        if (!result.isReplaySuccess()) {
            result.setApproved(false);
            result.setStatus(InfluenceStatus.NOT_INFLUENTIAL);
            result.setApprovalReason("Replay failed");
            log.debug("Rejected: {}", result.getApprovalReason());
            return result;
        }

        // Approved
        result.setApproved(true);
        result.setStatus(InfluenceStatus.INFLUENTIAL);
        result.setApprovalReason(String.format(
                "Approved: score=%.3f, mutable=true, replay=ok", result.getInfluenceScore()));
        return result;
    }
}
