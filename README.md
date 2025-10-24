# HARDEND - Linux Security Hardening Assessment Tool

**Author:** Constantine
**Email:** constantine.ctf@proton.me
**Version:** 2.0.0

A comprehensive, enterprise-grade Linux security assessment framework designed for system administrators and security professionals.

## Overview

**HARDEND** is a professional Linux security hardening assessment tool that provides automated, in-depth security analysis for Linux systems. Built entirely in Go, it delivers structured assessments focusing on configuration weaknesses, aligned with industry best practices.

The tool performs checks across key areas including **kernel parameters**, **running services**, **SSH configuration**, and **filesystem security** to identify potential vulnerabilities and provide actionable remediation guidance based on established security benchmarks.

## Key Features

### 🔒 Professional Security Assessment
- **Comprehensive Coverage**: Analyzes kernel hardening, service security, SSH configuration, and filesystem mount options.
- **Industry Standards Alignment**: Checks are mapped to **CIS Benchmarks** and **NIST security guidelines**, providing authoritative results.
- **Risk Scoring**: Findings are categorized using standard severity levels (**CRITICAL**, **HIGH**, **MEDIUM**, **LOW**) to prioritize remediation.
- **Multiple Output Formats**: Generates reports in human-readable **table** format, machine-readable **JSON**, and shareable **HTML**.

### ⚙️ Enterprise Capabilities
- **Zero Dependencies**: Deploys as a single, static Go binary with no external runtime requirements.
- **Stealth Mode**: Offers a mode with reduced system interaction for use in sensitive environments.
- **Cross-Platform**: Designed for various Linux distributions and containerized environments.
- **Configurable Architecture**: Assessment behavior is driven by a central YAML configuration file.
- **Performance Optimized**: Built for fast execution with minimal system impact.

## Architecture

### Directory Structure

```
hardend/
├── cmd/hardend/
│   └── main.go                 # Application entry point
├── pkg/
│   ├── checks/                 # Security check modules
│   │   ├── types.go            # Core data structures (Finding, Result, Severity)
│   │   ├── kernel.go           # Kernel parameter analysis
│   │   ├── services.go         # Service security analysis
│   │   ├── ssh.go              # SSH configuration analysis
│   │   ├── filesystem.go       # Filesystem mount analysis
│   │   └── runner.go           # Check orchestration logic
│   ├── config/
│   │   └── config.go           # Configuration loading and validation
│   ├── report/
│   │   └── report.go           # Report generation (Table, JSON, HTML)
│   └── utils/
│       └── utils.go            # Utility functions (logging, commands)
├── configs/
│   └── config.yaml             # Default configuration and security rules
├── go.mod                      # Go module dependencies
├── install.sh                  # Installation script
└── README.md                   # This documentation
```

### Technical Stack
- **Language**: Go 1.25+
- **Architecture**: Modular checker system driven by configuration.
- **Dependencies**: Minimal external dependencies (`yaml.v3`, `golang.org/x/sys`).

## Security Modules

### 1. Kernel Parameter Analysis (`kernel`)
**Purpose**: Assess critical kernel runtime parameters (`sysctl`) against security best practices.

**Key Areas**:
- Memory protection settings (e.g., ASLR via `kernel.randomize_va_space`).
- Network security parameters (e.g., IP forwarding, SYN cookies, source routing).
- Information leak prevention (e.g., dmesg restrictions, kernel pointer obfuscation).

### 2. Service Security Analysis (`services`)
**Purpose**: Audit running and enabled system services (`systemd`) against lists of prohibited and required services.

**Key Areas**:
- Identification of insecure legacy services (e.g., `telnet`, `rsh`).
- Verification that essential security services are active (e.g., `sshd`, `auditd`).

### 3. SSH Configuration Analysis (`ssh`)
**Purpose**: Audit the SSH daemon configuration (`/etc/ssh/sshd_config`) based on security hardening guidelines.

**Key Areas**:
- Protocol version enforcement (Protocol 2).
- Authentication methods (disabling root login, password authentication).
- Session security settings (timeouts, max tries).
- Use of secure cryptographic algorithms (future enhancement).

### 4. Filesystem Security Analysis (`filesystem`)
**Purpose**: Assess filesystem mount options and types for security risks.

**Key Areas**:
- Verification of secure mount options (`nosuid`, `noexec`, `nodev`) on critical partitions (`/tmp`, `/var/tmp`, `/dev/shm`, `/home`).
- Detection of potentially dangerous filesystem modules being loaded or available.
- Analysis of partition layout and use of encryption (basic check).

## Installation

### Quick Installation
```bash
# Clone repository
git clone https://github.com/ConstantineCTF/hardend.git  # Replace with your repo URL
cd hardend

# Run installation script (builds the binary)
chmod +x install.sh
./install.sh
# Follow prompts (optional system-wide install)
```

## Usage

### Basic Security Assessment

```bash
# Full system assessment using modules enabled in config.yaml
./hardend

# Run specific security modules
./hardend -scans kernel,ssh

# Silent mode for scripting (suppresses stdout logging)
./hardend --quiet

# Stealth mode (reduces system interaction, may affect results)
./hardend --stealth
```

### Report Generation

```bash
# Generate default table report to stdout (no color)
./hardend -format table --no-color > report.txt

# Generate structured JSON report
./hardend -format json -output security_assessment.json

# Generate HTML report
./hardend -format html -output security_report.html

# Use a custom configuration file
./hardend --config /path/to/custom_config.yaml
```

### Command Line Options

  - `-scans <modules>`: Comma-separated list of modules to run (e.g., `kernel,services`). Defaults to modules enabled in config.
  - `-config <path>`: Path to a custom YAML configuration file. Defaults to `configs/config.yaml`.
  - `-format <type>`: Output format (`table`, `json`, `html`). Defaults to `table`.
  - `-output <path>`: File path to save the report. Defaults to stdout.
  - `--verbose`: Enable detailed debug logging.
  - `--quiet`: Suppress informational logging to stdout.
  - `--stealth`: Use less intrusive methods for checks (may be less accurate).
  - `--version`: Show application version.
  - `--help`: Display help message.

## Configuration

The tool's behavior is primarily controlled by `configs/config.yaml`. This file defines:

  - Which security checks to run for each module.
  - Expected secure values for parameters.
  - Severity levels and references (e.g., CIS benchmarks) for findings.
  - Which modules are enabled by default.

See the default `configs/config.yaml` file for detailed structure and examples.

## Security Assessment Capabilities

### Hardening Checks

  - **Vulnerability Identification**: Detects specific configuration weaknesses based on defined rules.
  - **Compliance Alignment**: Maps findings to **CIS Benchmark** and **NIST guideline** references where applicable.
  - **Configuration Analysis**: Identifies deviations from the expected secure baseline defined in the configuration.

### Reporting Features

  - **Prioritized Findings**: Results are presented with severity levels (**CRITICAL**, **HIGH**, **MEDIUM**, **LOW**).
  - **Technical Details**: Includes actual vs. expected values for failed checks.
  - **Remediation Guidance**: Provides basic commands or configuration changes to fix identified issues.

### Assessment Categories (Severity)

  - **CRITICAL**: Critical misconfiguration likely leading to compromise (e.g., ASLR disabled, root SSH enabled).
  - **HIGH**: Serious weakness violating security best practices (e.g., password auth enabled, insecure kernel parameter).
  - **MEDIUM**: Configuration issue that reduces defense-in-depth (e.g., missing mount options).
  - **LOW**: Minor issue or best practice deviation.
  - **INFO**: Informational finding, not a vulnerability.

## Use Cases

### System Administration & DevOps

  - **Baseline Auditing**: Establish and verify security baselines across servers.
  - **Configuration Drift Detection**: Identify unintended configuration changes.
  - **Hardening Verification**: Confirm that hardening scripts or policies have been applied correctly.
  - **Pre-Deployment Checks**: Assess VM or container images before production deployment.

### Security Operations & Compliance

  - **Vulnerability Assessment**: Identify configuration-based vulnerabilities.
  - **Compliance Reporting**: Provide evidence for compliance audits (using CIS/NIST references).
  - **Risk Management**: Prioritize remediation efforts based on severity.

### CI/CD Integration

  - Integrate `hardend` into pipelines to automatically assess builds or infrastructure changes.

<!-- end list -->

```yaml
# Example GitLab CI stage
security_audit:
  stage: test
  script:
    - ./hardend --quiet -format json -output hardend_results.json
  artifacts:
    paths: [hardend_results.json]
```

## Deployment Options

### Standalone Binary

  - Build using `go build` or the `install.sh` script.
  - Copy the single `hardend` binary to the target Linux system and execute.

### Containerized Deployment

```bash
# Build the Docker image
docker build -t hardend:latest .

# Run against the host system (read-only mount)
docker run --rm --pid=host --net=host -v /:/hostfs:ro hardend:latest ./hardend --config /hostfs/path/to/config.yaml
# Note: Container checks will be limited by container isolation. Running directly on the host is more comprehensive.
```

## Performance and Security

### System Requirements

  - **Operating System**: Linux (tested on Ubuntu, Debian, CentOS; others likely compatible).
  - **Architecture**: x86\_64, ARM64 supported.
  - **Memory**: Minimal RAM usage (< 32MB typical).
  - **Permissions**: Requires root privileges (`sudo`) for most checks to access system files and configurations accurately. Running as non-root will result in skipped or inaccurate checks.
  - **Network**: No external network connectivity required for core operation.

### Security Considerations

  - **Read-Only Operations**: The tool primarily performs read operations on system files and configurations.
  - **Command Execution**: Uses standard Linux commands (`sysctl`, `systemctl`, `ss`, `mount`, etc.) for checks when run without `--stealth`. Stealth mode attempts to use `/proc` and direct file reads where possible.
  - **Data Privacy**: No data is transmitted externally. Reports are generated locally.

## Development and Extension

### Adding Custom Security Checks

1.  Define a new struct (e.g., `MyChecker`) in a new file within `pkg/checks/`.
2.  Implement the `Checker` interface: `func (mc *MyChecker) RunChecks(results *checks.Results) error`.
3.  Inside `RunChecks`, perform your checks and use `results.AddFinding(&checks.Finding{...})` to record issues.
4.  Register your new checker in `pkg/checks/runner.go` within the `NewRunner` function: `r.checkers["mycheck"] = NewMyChecker(...)`.
5.  Add configuration options for your check in `configs/config.yaml` and `pkg/config/config.go`.
6.  Enable the module via the `-scans` flag or in `config.yaml`.

### Contributing Guidelines

1.  Adhere to standard Go coding practices (`gofmt`, `golint`).
2.  Add unit tests for new functionality where applicable.
3.  Document the rationale for new checks, including references to security guidelines (CIS, NIST, etc.).
4.  Ensure new checks include clear remediation guidance in the `Finding` struct.

## Dependencies

### Runtime Dependencies

  - `gopkg.in/yaml.v3`: For parsing `config.yaml`.
  - `golang.org/x/sys`: For some system-level interactions.

### Development Dependencies

  - Go 1.25 or higher.
  - Standard Linux command-line utilities (used by the checks).
  - Git.

## License and Support

This project is licensed under the MIT License - see the `LICENSE` file for details.

### Support and Documentation

  - **Issues**: Report bugs or request features via the project's GitHub Issues page.
  - **Documentation**: Refer to this README and comments within the code.

### Security Reporting

If you discover a security vulnerability within HARDEND itself:

  - Please email constantine.ctf@proton.me directly.
  - Allow reasonable time for acknowledgment and resolution before public disclosure.

## Roadmap

### Current Version (v2.0.0)

  - Refactored codebase for professional clarity.
  - Core hardening modules: Kernel, Services, SSH, Filesystem.
  - Standardized reporting: Table, JSON, HTML.
  - Configuration-driven checks based on `config.yaml`.

### Future Enhancements

  - **Load Check Rules from Config**: Modify checkers (`ssh.go`, `kernel.go`, etc.) to dynamically load their rules from the `KernelConfig`, `SSHConfig` sections in `config.yaml` instead of having them hard-coded.
  - **Implement Remaining Modules**: Build out checkers for Network, Users, Permissions, SUID, Packages, Logs, Firewall, SELinux, Cron, Boot as defined in `config.yaml`.
  - **Enhanced Reporting**: Add scoring calculations, improved HTML report structure, potential integration templates (e.g., CSV).
  - **Unit Testing**: Expand test coverage, particularly for checker logic.
  - **Container-Specific Checks**: Add checks relevant when running inside containers.

-----

**HARDEND v2.0.0 - Professional Linux Security Assessment Framework**
*Automated hardening checks aligned with industry standards.*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
```
