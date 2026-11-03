# CyberSentinel Architecture & Web Cybersecurity Guidelines

CyberSentinel is an advanced multi-agent cybersecurity framework consisting of:
- **CyberSentinelMaster**: Orchestrates the multi-agent scanning pipeline.
- **CodeAuditAgent**: Static Application Security Testing (SAST), hardcoded secrets detection, and unsafe construct analysis (`eval`, `shell=True`).
- **InfraScanAgent**: Infrastructure misconfiguration auditing for Dockerfiles and Kubernetes manifests.
- **WebVulnScanAgent**: Advanced web vulnerability scanner covering OWASP Top 10 (SQLi, XSS, SSRF, Path Traversal, weak JWT secrets, insecure CORS) and HTTP security header / cookie audits.
- **SbomAgent**: Live SBOM dependency vulnerability analysis via OSV.dev CVE intelligence.
- **ReportAgent**: Generates professional Markdown and JSON security reports.

## Web Cybersecurity Pipeline

When executing a security scan on a web application target or codebase:
1. `CodeAuditAgent` inspects code quality and secrets.
2. `InfraScanAgent` checks container and cloud configurations.
3. `WebVulnScanAgent` audits web routes, APIs, OWASP top 10 patterns, HTTP headers/cookies, and performs deep iterative endpoint probing.
4. `SbomAgent` queries live CVE databases for open-source dependency vulnerabilities.
5. `ReportAgent` synthesizes findings into a risk-scored report.

## Deep Analysis & Continuous Improvement Mandate
- **No Surface-Level Shortcuts:** Scans must never stop at simple initial checks; agents must iteratively probe, analyze headers, check assets, and verify attack surfaces thoroughly.
- **Relentless Persistence:** If an initial check or scan fails to find a vulnerability or encounters an obstacle, agents must not give up or take shortcuts. They must iteratively search, adapt heuristics/fuzz vectors, pivot attack strategies, and persist until vulnerabilities or root causes are uncovered.
- **Empirical Proof & Validation:** Every finding, security scan result, or bug fix must be rigorously verified with concrete proof, reproduction tests, and empirical evidence before concluding.
- **Time-Bound Continuous Scanning & Testing:** Agents can be instructed to run continuous deep scans, iterative fuzzing loops, and multi-angle security probes for a specific period of time (e.g. scanning continuously for X minutes/hours/days) or until deep vulnerabilities and empirical proof are fully established.
- **Time-Bound Continuous Self-Upgrading:** Agents can be instructed to continuously upgrade codebase capabilities, enhance scanning heuristics, add test coverage, refactor modules, and optimize logic for a specified duration (e.g., 1 hour, a day, or longer) or until perfection is achieved.
- **Continuous Self-Improvement:** Agents and scanning logic must continuously adapt heuristics, fuzz vectors, and validation patterns to ensure maximum depth and coverage.
