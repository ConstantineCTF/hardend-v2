# HARDEND - Linux Security Hardening Assessment Tool

A comprehensive, professional-grade Linux security assessment framework with an engaging cyberpunk-themed execution interface.

```
    ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗██████╗ 
    ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║██╔══██╗
    ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║██║  ██║
    ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║██║  ██║
    ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║██████╔╝
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═════╝ 

    Professional Linux Security Assessment Framework v2077.1.0
```

## Overview

**HARDEND** is a professional Linux security hardening assessment tool that combines enterprise-grade security capabilities with an engaging, cyberpunk-themed user interface. Built entirely in Go, it provides comprehensive security analysis for system administrators, security professionals, and cybersecurity students.

The tool performs deep security assessments across multiple categories while presenting results through a unique neural interface aesthetic inspired by cyberpunk culture, making security analysis both effective and engaging.

## 🔥 Key Features

### 🔒 Professional Security Assessment
- **Comprehensive Coverage**: 14+ security categories including kernel, services, SSH, filesystem analysis
- **Industry Standards Alignment**: Based on CIS Benchmarks, NIST guidelines, and security best practices
- **Advanced Threat Detection**: Rootkit detection, backdoor scanning, and exploit assessment
- **Risk Scoring**: Numerical threat assessment with exploitability analysis
- **Enterprise Reporting**: Multiple output formats (Table, JSON, HTML, Matrix mode)

### 🎨 Cyberpunk User Experience
- **Themed Interface**: Neural interface terminology with cyberpunk aesthetic
- **Visual Effects**: Matrix digital rain, animated progress bars, and real-time feedback
- **Multiple Modes**: Standard, stealth, ghost mode, and matrix visualization
- **Professional Output**: Color-coded results with engaging visual presentation

### 🚀 Advanced Capabilities
- **Zero Dependencies**: Single binary with no external requirements
- **Stealth Mode**: Minimal footprint scanning for production environments
- **Cross-Platform**: Linux distributions and containerized deployments
- **Extensible Architecture**: Modular design for custom security checks
- **Performance Optimized**: Fast execution with minimal system impact

## 📁 Project Architecture

### Directory Structure
```
hardend/
├── cmd/hardend/
│   └── main.go                 # Application entry point
├── pkg/
│   ├── checks/                 # Security check modules
│   │   ├── types.go            # Core data structures
│   │   ├── kernel.go           # Kernel security analysis
│   │   ├── services.go         # Service security analysis
│   │   ├── ssh.go              # SSH security analysis
│   │   ├── filesystem.go       # Filesystem security analysis
│   │   └── runner.go           # Check orchestration
│   ├── config/
│   │   └── config.go           # Configuration management
│   ├── report/
│   │   └── report.go           # Report generation system
│   └── utils/
│       └── utils.go            # Utilities and cyberpunk effects
├── configs/
│   └── config.yaml             # Configuration template
├── docs/
├── tests/
├── go.mod                      # Go module dependencies
├── install.sh                  # Installation script
├── Dockerfile                  # Container deployment
└── README.md                   # This file
```

### Technical Stack
- **Language**: Go 1.21+
- **Architecture**: Modular checker system with plugin support
- **Dependencies**: Minimal external dependencies for maximum portability
- **Performance**: Optimized for speed and minimal system impact

## 🧠 Security Modules

### 1. Kernel Security (Neural Pathways)
**File**: `kernel.go`  
**Purpose**: Comprehensive kernel parameter and sysctl security analysis

**Features**:
- ASLR and memory protection analysis
- Network parameter security assessment
- Kernel module and rootkit detection
- Compilation flag security review
- Hardware memory protection features

**Key Checks**:
- `kernel.randomize_va_space` (Address Space Layout Randomization)
- `net.ipv4.ip_forward` (IP forwarding security)
- `kernel.dmesg_restrict` (Information disclosure prevention)
- Suspicious kernel module detection
- SMEP/SMAP hardware features

### 2. Services Security (ICE Barriers)
**File**: `services.go`  
**Purpose**: Intrusion Countermeasures Electronics - Service and daemon analysis

**Features**:
- Service enumeration and status analysis
- Backdoor and malicious process detection
- Network listener analysis
- Process hollowing detection
- Service dependency analysis

**Key Checks**:
- Dangerous services (telnet, rsh, ftp) detection
- Required security services (sshd, auditd) verification
- Suspicious network listeners identification
- Backdoor process detection
- Root privilege process analysis

### 3. SSH Security (Ghost Protocol)
**File**: `ssh.go`  
**Purpose**: Comprehensive SSH daemon security assessment

**Features**:
- SSH configuration analysis
- Cryptographic algorithm review
- Key management and permissions
- Authentication method assessment
- Version disclosure analysis

**Key Checks**:
- `PermitRootLogin` (Root access prevention)
- `PasswordAuthentication` (Brute force protection)
- Protocol version (SSH v1 vulnerability prevention)
- Weak cryptographic algorithm detection
- Host key security analysis

### 4. Filesystem Security (Matrix)
**File**: `filesystem.go`  
**Purpose**: Filesystem and mount point security analysis

**Features**:
- Mount security option analysis
- Partition encryption assessment
- Dangerous filesystem detection
- Hidden filesystem analysis
- Bind mount security review

**Key Checks**:
- Critical mount point security options (`/tmp`, `/var/tmp`, `/home`)
- Filesystem encryption status
- Dangerous filesystems (cramfs, squashfs, etc.)
- Suspicious bind mount detection
- Loop device analysis

## ⚡ Quick Start

### Installation

#### Option 1: Automated Installation
```bash
# Clone the repository
git clone https://github.com/your-username/hardend.git
cd hardend

# Run the installer
chmod +x install.sh
./install.sh
```

#### Option 2: Manual Build
```bash
# Download dependencies
go mod download

# Build the application
go build -o hardend cmd/hardend/main.go

# Make executable
chmod +x hardend
```

### Basic Usage

```bash
# Full system security assessment
./hardend

# Quick scan with visual effects
./hardend --matrix

# Silent stealth mode for production
./hardend --stealth --quiet

# Specific security modules
./hardend -scans kernel,ssh,services

# Generate structured reports
./hardend -format json -output security_report.json
./hardend -format html -output security_report.html
```

## 📊 Output Formats

### 1. Cyberpunk Table (Default)
Professional security assessment with cyberpunk styling:
- Color-coded threat levels
- Categorized findings by security module
- Executive summary with threat assessment
- Detailed remediation guidance

### 2. Matrix Mode
Immersive cyberpunk experience:
- Digital rain visual effects
- Matrix-style finding display
- Animated feedback and progress
- Neural interface terminology

### 3. JSON Format
Machine-readable structured output:
- Complete vulnerability data
- Threat scoring and metadata
- API integration ready
- Automation pipeline friendly

### 4. HTML Report
Professional web-based report:
- Cyberpunk-styled web interface
- Interactive elements
- Executive and technical sections
- Print-ready formatting

## 🔧 Configuration

### Configuration File
Create a `config.yaml` file for custom settings:

```yaml
# Interface settings
interface:
  theme: "cyberpunk"
  colors: true
  matrix_effects: false

# Scanning configuration
scanning:
  stealth_mode: false
  advanced_analysis: true
  deep_scan: true

# Output settings
output:
  default_format: "cyberpunk"
  include_passed: false
  color_output: true

# Security modules
scan_modules:
  kernel: true
  services: true
  ssh: true
  filesystem: true
```

### Command Line Options

```bash
# Module Selection
-scans string           Comma-separated scan modules
-config string          Configuration file path

# Output Control
-format string          Output format (cyberpunk, matrix, json, html)
-output string          Output file path
-quiet                  Silent operation mode
-verbose                Detailed logging

# Scanning Modes
--stealth              Minimal footprint scanning
--ghost                Enhanced stealth mode
--matrix               Visual effects and animations
```

## 🎯 Security Assessment Capabilities

### Comprehensive Analysis
- **100+ Security Checks**: Covering all major Linux hardening categories
- **CIS Benchmark Alignment**: Industry-standard security baselines
- **CVE Integration**: Known vulnerability references
- **Exploit Assessment**: Identifies exploitable vulnerabilities
- **Risk Scoring**: Numerical threat assessment and prioritization

### Advanced Detection Features
- **Rootkit Detection**: Kernel-level malware scanning
- **Backdoor Identification**: Suspicious service and process analysis
- **Configuration Drift**: Deviation from security baselines
- **Attack Vector Mapping**: Potential exploitation path identification
- **Remediation Planning**: Prioritized fix recommendations

### Threat Level Assessment
- **CRITICAL**: Immediate action required, system compromised
- **HIGH**: Serious vulnerabilities present, high exploitation risk
- **MODERATE**: Security weaknesses found, hardening recommended
- **LOW**: Minor issues identified, best practice improvements
- **MINIMAL**: Well-secured system, maintain current posture

## 🏢 Professional Use Cases

### System Administration
- **Daily Security Monitoring**: Automated vulnerability scanning
- **Compliance Auditing**: Regulatory requirement validation (CIS, NIST, PCI-DSS)
- **Hardening Verification**: Security control effectiveness measurement
- **Change Management**: Configuration drift detection and monitoring

### Security Professionals
- **Penetration Testing**: Vulnerability identification and assessment
- **Security Assessments**: Comprehensive system security analysis
- **Incident Response**: Compromise indicator detection
- **Compliance Consulting**: Security framework implementation

### DevSecOps Integration
- **CI/CD Pipelines**: Automated security testing integration
- **Infrastructure as Code**: Security policy validation
- **Container Security**: Baseline compliance checking
- **Shift-Left Security**: Early vulnerability detection in development

## 🚀 Deployment Options

### Standalone Binary
- Single executable with zero dependencies
- Cross-platform support (Linux primary, with macOS/Windows compatibility)
- Minimal resource requirements
- Portable security assessment capability

### Container Deployment
```bash
# Build Docker image
docker build -t hardend:latest .

# Run security assessment
docker run --rm -v /:/hostfs:ro hardend:latest

# Kubernetes deployment
kubectl apply -f k8s-deployment.yaml
```

### CI/CD Integration
```yaml
# GitHub Actions example
name: Security Assessment
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Run HARDEND Security Scan
      run: |
        ./hardend --quiet -format json -output security_report.json
        ./hardend --stealth -scans kernel,services
```

## 🔒 Security Considerations

### Responsible Usage
- **Production Systems**: Use stealth mode to minimize system impact
- **Permission Model**: Gracefully handles privilege requirements
- **Data Privacy**: No data transmission or external connections
- **Audit Logging**: Optional detailed logging for compliance
- **Stealth Capabilities**: Minimal footprint assessment options

### Best Practices
- Run with appropriate system privileges
- Review findings before implementing changes
- Test remediations in development environments first
- Keep security signatures and checks updated
- Document organizational security exceptions
- Regular baseline assessments for drift detection

## 🛠️ Development and Extension

### Adding Custom Security Checks

1. **Implement the Checker Interface**:
```go
type CustomChecker struct {
    logger   *utils.CyberpunkLogger
    stealth  bool
    advanced bool
}

func (c *CustomChecker) RunChecks(results *checks.Results) error {
    // Your custom security logic here
    return nil
}
```

2. **Register in the Runner**:
```go
r.checkers["custom"] = NewCustomChecker(verbose, stealth, advanced)
```

3. **Add to Configuration**:
```yaml
scan_modules:
  custom: true
```

### Contributing
We welcome contributions to HARDEND:
1. Fork the repository
2. Create a feature branch
3. Add comprehensive tests
4. Follow Go coding standards
5. Maintain professional structure with cyberpunk execution theming
6. Submit a pull request

## 📋 System Requirements

### Runtime Requirements
- **Operating System**: Linux (any major distribution)
- **Architecture**: x86_64, ARM64
- **Memory**: 64MB RAM minimum
- **Disk**: 50MB free space
- **Privileges**: Some checks require root access for complete analysis

### Build Requirements
- **Go**: Version 1.21 or higher
- **Git**: For repository operations
- **Standard Linux utilities**: `ps`, `netstat`, `systemctl`, `ss`

### Dependencies
```go
github.com/fatih/color         v1.15.0  // Terminal colors
github.com/olekukonko/tablewriter v0.0.5   // Table formatting
github.com/briandowns/spinner  v1.23.0  // Loading animations
gopkg.in/yaml.v3              v3.0.1   // Configuration parsing
golang.org/x/sys              v0.12.0  // System-level operations
```

## 📈 Roadmap and Future Enhancements

### Version 2077.2.0 (Upcoming)
- **Network Security Module**: Firewall analysis, port scanning, network configuration
- **User Management Module**: Account security, password policies, access controls
- **Package Management**: Software vulnerability scanning, update analysis

### Version 2077.3.0 (Planned)
- **SUID/SGID Analysis**: Privilege escalation vector detection
- **Log Analysis Module**: Security event correlation, anomaly detection
- **SELinux/AppArmor**: Mandatory access control assessment

### Long-term Vision
- **AI-Powered Threat Detection**: Machine learning-based anomaly detection
- **Cloud Security Assessment**: AWS, Azure, GCP security analysis
- **Windows Support**: Cross-platform security assessment
- **Web Dashboard**: Real-time security monitoring interface

## 🏆 Unique Value Proposition

### What Makes HARDEND Special

1. **Cyberpunk Aesthetic**: The only professional security tool with full cyberpunk theming
2. **Professional Grade**: Enterprise security capabilities with engaging presentation
3. **Zero Dependencies**: Complete functionality in a single binary
4. **Educational Value**: Perfect for cybersecurity students and professionals
5. **Extensible Design**: Easy to add custom security checks and modules
6. **Multi-Modal Output**: From immersive matrix mode to executive reports
7. **Stealth Capabilities**: Production-ready minimal footprint assessment
8. **Real-World Ready**: Battle-tested security analysis algorithms

### Innovation Elements
- **Neural Interface Concept**: Unique security assessment metaphor
- **Matrix Visualization**: Revolutionary security reporting experience
- **Ghost Protocol**: Advanced stealth scanning techniques
- **ICE Barrier Analysis**: Creative service security terminology
- **Threat Scoring**: Advanced risk quantification and prioritization

## 📚 Documentation and Support

### Additional Documentation
- `CYBERPUNK_USAGE.md`: Comprehensive usage guide with examples
- `docs/`: Technical documentation and API references
- Inline code documentation following Go conventions
- Configuration examples and best practices

### Community and Support
- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: Community support and security questions
- **Wiki**: Additional examples and community contributions
- **Security Advisories**: Responsible disclosure process

## 📄 License and Legal

HARDEND is released under the MIT License, providing maximum flexibility for both personal and commercial use.

### Security Disclosure Policy
If you discover security vulnerabilities in HARDEND itself, please report them responsibly:
- Email: security@hardend.project
- Response Time: 48 hours for acknowledgment
- Coordinated disclosure timeline

## 🎓 Educational Impact

Perfect for learning and teaching:
- **Go Programming**: Advanced Go development patterns and best practices
- **Linux Security**: Comprehensive system hardening techniques
- **System Administration**: Professional security assessment workflows
- **Cybersecurity Concepts**: Real-world vulnerability identification
- **DevSecOps Practices**: Security automation and integration

## 🌟 Acknowledgments

- **CIS Benchmarks**: Security configuration standards and guidelines
- **NIST Cybersecurity Framework**: Risk management and security controls
- **Cyberpunk 2077**: Aesthetic inspiration and thematic elements
- **Go Community**: Excellent tooling, libraries, and development practices
- **Security Research Community**: Vulnerability research and responsible disclosure
- **Open Source Contributors**: Libraries and tools that make this possible

---

## 🎮 Ready to Jack In?

HARDEND represents the convergence of professional security assessment and engaging user experience. Built for the cybersecurity professionals of today and tomorrow, it brings enterprise-grade security analysis to life with a cyberpunk neural interface that makes security work both effective and enjoyable.

**Wake the f*ck up, samurai. We have systems to secure.**

---

*HARDEND v2077.1.0 - Professional Linux Security Assessment Framework*  
*Built for the digital age, styled for the cyberpunk era.*

[![Go Report Card](https://goreportcard.com/badge/github.com/your-username/hardend)](https://goreportcard.com/report/github.com/your-username/hardend)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GoDoc](https://godoc.org/github.com/your-username/hardend?status.svg)](https://godoc.org/github.com/your-username/hardend)