package com.aiburpcopilot.core.discovery;

import java.util.List;

public interface ISiteDiscoveryService {

    List<String> listHosts();

    List<DiscoveryCandidate> getCandidates(String hostFilter);

    List<DiscoveryCandidate> inferCandidates(String hostFilter);

    DiscoveryCandidate validateCandidate(DiscoveryCandidate candidate);

    String describeEndpointStructure(String hostFilter);
}
