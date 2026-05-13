package com.aiburpcopilot.core.verification.influence;

import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.verification.model.CandidateParameter;
import com.aiburpcopilot.core.verification.model.ParameterProfile;

public interface IParameterRoleAnalyzer {

    ParameterRole analyze(HTTPContext context,
                          CandidateParameter candidate,
                          ParameterProfile profile);
}
