package com.aiburpcopilot.core.discovery;

import java.util.List;

public interface ISiteDiscoveryService {

    List<String> listHosts();

    List<DiscoveryCandidate> getCandidates(String hostFilter);

    DiscoveryCandidate validateCandidate(DiscoveryCandidate candidate);
}
