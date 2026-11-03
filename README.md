# CyberSentinel 🛡️

CyberSentinel is an advanced, modular cybersecurity agent and subagents framework designed to perform automated vulnerability scanning, static application security testing (SAST), infrastructure misconfiguration auditing, advanced web vulnerability assessment, and professional security reporting.

## Features

- **CyberSentinelMaster**: Intelligent orchestrator agent that coordinates multi-agent security assessments.
- **CodeAuditAgent**: Scans source code and dependency files for hardcoded secrets, unsafe patterns, and known vulnerable dependencies.
- **InfraScanAgent**: Audits Dockerfiles, Kubernetes manifests, and cloud configuration files for security misconfigurations.
- **WebVulnScanAgent**: Performs advanced web vulnerability scanning (OWASP Top 10 SAST covering SQLi, XSS, SSRF, Path Traversal, weak JWT secrets, insecure CORS, and active/passive URL header & cookie audits).
- **ReportAgent**: Generates comprehensive, scored security reports in Markdown and JSON formats with actionable remediation advice.

## Installation

```bash
pip install -e .
```

## Usage

```bash
cybersentinel scan <target_directory_or_url>
```

### Background Scanning Missions (Tmux)

CyberSentinel supports running long-running scans in the background using `tmux` sessions. This allows you to disconnect from your terminal without interrupting the scan.

#### Commands:
- **Start Mission**: 
  ```bash
  cybersentinel mission start <target>
  ```
- **Check Status**: 
  ```bash
  cybersentinel mission status
  ```
- **View Live Logs**: 
  ```bash
  cybersentinel mission logs
  ```
- **Attach to Session**: 
  ```bash
  cybersentinel mission attach
  ```

### GitHub Actions Automated Background Jobs & Progress Tracking

CyberSentinel includes a built-in GitHub Actions workflow (`.github/workflows/cybersentinel-scan.yml`) that runs automated security scans and test suites in the background on GitHub servers whenever you push code, open pull requests, or trigger manual workflow runs (`workflow_dispatch`).

#### How it works:
1. **Automated Background Jobs**: Every push or PR triggers GitHub Actions to run the full CyberSentinel deep scan pipeline and pytest suite in the cloud.
2. **Progress & Logs Tracking**: You can view real-time logs, progress steps, and pass/fail statuses directly in the **GitHub Actions tab** of your repository.
3. **Artifact Reports**: Upon completion, security reports are automatically packaged and uploaded as GitHub Artifacts (`cybersentinel-security-report`) which you can download and review.
4. **Manual Triggering**: You can go to **Actions** -> **CyberSentinel Security Scan & Test Mission** -> **Run workflow** to run a deep scan on any custom target directory at any time without tying up your local terminal.

#### Important Note on GitHub Codespaces:
- **Terminal Disconnection**: `tmux` successfully keeps your scan running if you close your browser tab, lose internet connection, or disconnect your SSH/terminal session, as long as the Codespace container remains running.
- **Codespace Inactivity Timeout**: If your GitHub Codespace stops due to inactivity (default inactivity timeout is typically 30 minutes), the entire container shuts down. When the container stops, active `tmux` sessions and their running processes are terminated. To run very long missions, ensure your Codespace stays active or use keep-alive tooling.

