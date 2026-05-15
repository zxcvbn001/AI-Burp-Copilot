# AI Burp Copilot v2

AI Burp Copilot v2 is an AI-assisted security analysis extension for Burp Suite.

It is designed to help testers analyze real HTTP traffic, verify suspected issues with rule-driven probes, and review evidence with LLM-assisted reasoning.  
It is **not** intended to replace human testing or act as an autonomous black-box scanner.

---

## Why This Project

Manual Burp testing is powerful, but repetitive verification work quickly becomes expensive:

- identifying which parameters are worth testing
- replaying similar probes across endpoints
- comparing responses and filtering noise
- turning intermediate evidence into reviewable conclusions

AI Burp Copilot v2 focuses on that gap.

It turns real Burp traffic into a workflow that is:

- **analyzable**
- **verifiable**
- **reviewable**
- **traceable**

---

## What It Does

AI Burp Copilot v2 combines deterministic verification with AI-assisted interpretation:

- captures and classifies Burp traffic
- analyzes endpoints, parameters, and attack surface
- evaluates whether a parameter appears to influence server behavior
- runs rule-based probes for supported vulnerability families
- preserves request/response evidence for every probe
- performs LLM-assisted secondary review where needed
- aggregates findings into exportable results

---

## Core Workflow

```text
Burp HTTP traffic
   |
   v
Endpoint identification
   |
   v
Attack surface analysis
   |
   v
Candidate parameters and attack types
   |
   v
Parameter influence evaluation
   |
   v
Rule-based probe verification
   |
   v
LLM-assisted review
   |
   v
Finding aggregation and reporting
```

---

## Supported Areas

The current rule set covers the following families:

- SQL Injection
- Cross-Site Scripting
- IDOR
- Auth / JWT issues
- Command Injection
- SSRF
- Path Traversal
- Open Redirect
- LDAP Injection
- GraphQL exposure checks
- File Upload
- CORS
- SSTI
- XXE

The project is strongest when used for:

- Burp-assisted manual testing
- parameter-level verification
- repeatable checks for known vulnerability classes
- evidence preservation and report generation

---

## Quick Start

### Requirements

- JDK 21
- Maven 3.9+

### Build

```bash
mvn -DskipTests package
```

Artifact:

```text
target/ai-burp-copilot-v2-jar-with-dependencies.jar
```

### Load into Burp

1. Open Burp Suite
2. Go to `Extensions -> Installed -> Add`
3. Choose extension type `Java`
4. Select `target/ai-burp-copilot-v2-jar-with-dependencies.jar`

### External Configuration

The plugin reads runtime assets from an external configuration directory:

```text
ai-burp-copilot/
├─ application.yml
├─ prompts/
├─ rules/
└─ 报告模板.docx
```

After loading the extension, select this directory in the plugin settings.

---

## Documentation

Public project docs:

- `docs/rule-authoring.md`
- `docs/workflow-overview.md`
- `docs/ai-workflow-flowchart.md`

---

## Design Principles

This project follows a few core principles:

- **HTTP-first verification**: replay, diff, and execution are generic capabilities, not tied to a single vulnerability type
- **rules before hardcoding**: new detection logic should prefer external rules over Java-side specialization
- **LLM as reviewer, not controller**: AI suggests, explains, and reviews; it should not freely drive attack execution
- **evidence over intuition**: conclusions should be backed by preserved requests, responses, and rule hits

---

## Roadmap

Current improvement areas include:

- stronger final-decision logic across evidence sources
- better de-duplication and scheduling
- richer report generation
- improved rule coverage and tuning
- better UI visibility for probe history and evidence chains

---

## Security Notice

Use this project only in authorized environments.

This project is intended for:

- authorized security testing
- security research
- workflow and verification-engine evaluation

It must not be used for:

- unauthorized attacks
- destructive testing
- unlawful attempts to bypass real-world protections

---

## Project Status

AI Burp Copilot v2 already includes a working end-to-end pipeline covering:

- traffic intake
- endpoint analysis
- parameter evaluation
- rule-based verification
- LLM-assisted review
- finding aggregation
- UI presentation

It is no longer just a proof of concept, but it is still actively evolving.
