package com.aiburpcopilot.core.verification.probe;

import com.aiburpcopilot.core.context.AttackType;

import java.util.List;

public interface IProbeRuleEngine {

    List<ProbeDefinition> getProbes(AttackType attackType);

    void reload();
}
