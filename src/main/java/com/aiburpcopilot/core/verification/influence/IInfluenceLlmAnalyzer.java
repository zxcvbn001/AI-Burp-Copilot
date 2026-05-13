package com.aiburpcopilot.core.verification.influence;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.DiffResult;
import com.aiburpcopilot.core.verification.model.ParameterProfile;

public interface IInfluenceLlmAnalyzer {

    InfluenceLlmDecision analyze(AttackType attackType,
                                 String parameterName,
                                 String mutationValue,
                                 ParameterProfile profile,
                                 DiffResult diffResult,
                                 double deterministicScore);
}
