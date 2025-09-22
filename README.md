# HARDEND - Linux Security Hardening Assessment Tool

A comprehensive, enterprise-grade Linux security assessment framework for system administrators and security professionals.

## Overview

**HARDEND** is a professional Linux security hardening assessment tool that provides comprehensive security analysis across multiple categories. Built entirely in Go, it delivers enterprise-grade security assessments with detailed vulnerability analysis, risk scoring, and remediation guidance.

The tool performs deep security assessments across kernel parameters, service configurations, SSH security, and filesystem security to identify potential vulnerabilities and provide actionable remediation steps.

## Key Features

### 🔒 Professional Security Assessment
- **Comprehensive Coverage**: Kernel, services, SSH, and filesystem security analysis
- **Industry Standards**: Aligned with CIS Benchmarks and NIST security guidelines
- **Advanced Detection**: Rootkit detection, backdoor scanning, and exploit assessment
- **Risk Scoring**: Numerical threat assessment with exploitability analysis
- **Multiple Output Formats**: Structured reports in table, JSON, and HTML formats

### 🚀 Enterprise Capabilities
- **Zero Dependencies**: Single binary deployment with no external requirements
- **Stealth Mode**: Minimal footprint scanning for production environments
- **Cross-Platform**: Linux distributions and containerized deployments
- **Extensible Architecture**: Modular design for custom security checks
- **Performance Optimized**: Fast execution with minimal system impact

## Architecture

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
│   │   └── report.go           # Report generation
│   └── utils/
│       └── utils.go            # Utility functions
├── configs/
│   └── config.yaml             # Configuration template
├── go.mod                      # Go module dependencies
├── install.sh                  # Installation script
└── README.md                   # This documentation
```

### Technical Stack
- **Language**: Go 1.21+
- **Architecture**: Modular checker system
- **Dependencies**: Minimal external dependencies
- **Performance**: Optimized for enterprise environments

## Security Modules

### 1. Kernel Security Analysis
**Purpose**: Comprehensive kernel parameter and system-level security assessment

**Key Areas**:
- Memory protection mechanisms (ASLR, DEP, stack protection)
- Network parameter security configuration
- Kernel module integrity and rootkit detection
- System call restrictions and capabilities
- Hardware security feature utilization

### 2. Service Security Analysis  
**Purpose**: Service configuration and daemon security assessment

**Key Areas**:
- Running service enumeration and analysis
- Unnecessary service identification
- Service configuration security review
- Network listener analysis
- Process integrity verification

### 3. SSH Security Analysis
**Purpose**: SSH daemon configuration and cryptographic security assessment

**Key Areas**:
- SSH configuration parameter analysis
- Cryptographic algorithm strength assessment
- Authentication method security review
- Key management and permissions
- Protocol security and version analysis

### 4. Filesystem Security Analysis
**Purpose**: Filesystem and mount point security assessment

**Key Areas**:
- Mount point security options verification
- Filesystem type security analysis
- Partition layout and encryption assessment
- Hidden filesystem detection
- Storage security compliance

## Installation

### Quick Installation
```bash
# Clone repository
git clone https://github.com/ConstantineCTF/hardend.git
cd hardend

# Install using provided script
chmod +x install.sh
./install.sh
```

### Manual Build
```bash
# Download dependencies
go mod download

# Build application
go build -o hardend cmd/hardend/main.go

# Install system-wide (optional)
sudo cp hardend /usr/local/bin/
```

## Usage

### Basic Security Assessment
```bash
# Full system security assessment
./hardend

# Specific security modules
./hardend -scans kernel,ssh,services

# Silent mode for automated environments
./hardend --stealth --quiet
```

### Report Generation
```bash
# Generate structured JSON report
./hardend -format json -output security_assessment.json

# Generate HTML report for management
./hardend -format html -output security_report.html

# Custom configuration
./hardend --config custom_config.yaml
```

### Advanced Options
```bash
# Available output formats
./hardend -format table    # Default formatted table
./hardend -format json     # Machine-readable JSON
./hardend -format html     # Web-based report

# Scanning modes  
./hardend --stealth        # Minimal system footprint
./hardend --verbose        # Detailed logging output
./hardend --quiet          # Silent operation
```

## Configuration

### Configuration File Structure
```yaml
# Security scanning configuration
scanning:
  stealth_mode: false
  advanced_analysis: true
  deep_scan: true

# Output preferences  
output:
  default_format: "table"
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
- `-scans`: Specify security modules to run
- `-config`: Custom configuration file path
- `-format`: Output format (table, json, html)
- `-output`: Output file path
- `--stealth`: Minimal footprint mode
- `--quiet`: Silent operation
- `--verbose`: Detailed logging

## Security Assessment Capabilities

### Threat Detection
- **Vulnerability Identification**: Comprehensive security weakness detection
- **Risk Assessment**: Numerical scoring with exploitability analysis
- **Compliance Checking**: CIS Benchmark and NIST guideline verification
- **Configuration Analysis**: Security misconfigurations and drift detection

### Reporting Features
- **Executive Summaries**: High-level security posture assessment
- **Technical Details**: Detailed finding descriptions and evidence
- **Remediation Guidance**: Step-by-step fix instructions
- **Compliance Mapping**: Control framework alignment

### Assessment Categories
- **CRITICAL**: Immediate action required, system compromised
- **HIGH**: Serious vulnerabilities, high exploitation risk
- **MEDIUM**: Security weaknesses, hardening recommended  
- **LOW**: Minor issues, best practice improvements
- **INFO**: Informational findings and system details

## Enterprise Use Cases

### System Administration
- **Security Baseline Assessment**: Regular security posture evaluation
- **Compliance Auditing**: Regulatory requirement validation
- **Configuration Management**: Security drift detection and monitoring
- **Hardening Verification**: Security control effectiveness measurement

### Security Operations
- **Vulnerability Assessment**: Comprehensive security weakness identification
- **Incident Response**: Security compromise indicator detection
- **Risk Management**: Threat prioritization and remediation planning
- **Security Monitoring**: Continuous security posture assessment

### DevSecOps Integration
- **Pipeline Integration**: Automated security testing in CI/CD
- **Infrastructure Security**: Security policy validation
- **Container Assessment**: Baseline security compliance
- **Shift-Left Security**: Early vulnerability detection

## Deployment Options

### Standalone Deployment
- Single binary with zero dependencies
- Cross-platform compatibility
- Minimal resource requirements
- Portable security assessment

### Containerized Deployment
```bash
# Docker deployment
docker build -t hardend:latest .
docker run --rm -v /:/hostfs:ro hardend:latest

# Kubernetes integration
kubectl apply -f deployment.yaml
```

### Enterprise Integration
```yaml
# CI/CD Pipeline Integration
stages:
  - security_assessment:
      script:
        - ./hardend --quiet -format json -output security.json
        - ./hardend --stealth -scans kernel,services
```

## Performance and Security

### System Requirements
- **Operating System**: Linux (any major distribution)
- **Architecture**: x86_64, ARM64 supported
- **Memory**: 32MB RAM minimum
- **Permissions**: Some checks require elevated privileges
- **Network**: No external connectivity required

### Security Considerations
- **Data Privacy**: No external data transmission
- **Audit Logging**: Optional detailed operation logging
- **Minimal Footprint**: Designed for production environment use
- **Permission Handling**: Graceful privilege requirement management

## Development and Extension

### Adding Custom Security Checks
```go
// Implement the Checker interface
type CustomChecker struct {
    logger   *utils.Logger
    config   *config.Config
}

func (c *CustomChecker) RunChecks(results *checks.Results) error {
    // Custom security logic implementation
    return nil
}

// Register with the runner
runner.RegisterChecker("custom", NewCustomChecker())
```

### Contributing Guidelines
1. Follow Go coding standards and best practices
2. Include comprehensive test coverage
3. Document security check rationale and references
4. Maintain backward compatibility
5. Include remediation guidance for new checks

## Dependencies

### Runtime Dependencies
```go
github.com/fatih/color         // Terminal output formatting
github.com/olekukonko/tablewriter // Table generation
gopkg.in/yaml.v3              // Configuration parsing
golang.org/x/sys              // System-level operations
```

### Development Dependencies
- Go 1.21 or higher
- Standard Linux utilities (ps, netstat, systemctl)
- Git for version control

## License and Support

### License
This project is licensed under the MIT License - see the LICENSE file for details.

### Support and Documentation
- **Issues**: Report bugs and request features via GitHub Issues
- **Documentation**: Comprehensive guides in the docs/ directory
- **Community**: Join discussions and get support from the community

### Security Reporting
For security vulnerabilities in HARDEND itself:
- Email: security@hardend.project
- Response time: 48 hours for acknowledgment
- Coordinated disclosure process

## Roadmap

### Current Version (v2077.1.0)
- Core security modules (Kernel, Services, SSH, Filesystem)
- Multiple output formats
- Professional reporting capabilities
- Enterprise deployment support

### Upcoming Features
- Network security assessment module
- User and permission analysis
- Package vulnerability scanning
- Enhanced compliance reporting
- Cloud security assessment capabilities

---

**HARDEND v2077.1.0 - Professional Linux Security Assessment Framework**  
*Built for enterprise security professionals and system administrators*

[![Go Report Card](https://goreportcard.com/badge/github.com/ConstantineCTF/hardend)](https://goreportcard.com/report/github.com/ConstantineCTF/hardend)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GoDoc](https://godoc.org/github.com/ConstantineCTF/hardend?status.svg)](https://godoc.org/github.com/ConstantineCTF/hardend)