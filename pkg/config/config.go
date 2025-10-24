package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	Application ApplicationConfig `yaml:"application"`
	Kernel      KernelConfig      `yaml:"kernel_parameters"`
	Services    ServicesConfig    `yaml:"services"`
	SSH         SSHConfig         `yaml:"ssh_security"`
	Filesystem  FilesystemConfig  `yaml:"filesystem"`
	Output      OutputConfig      `yaml:"output"`
	Scanning    ScanningConfig    `yaml:"scanning"`
	Threat      ThreatConfig      `yaml:"threat_assessment"`
	Modules     ModulesConfig     `yaml:"scan_modules"`
	Reporting   ReportingConfig   `yaml:"reporting"`
}

// ApplicationConfig contains basic application information
type ApplicationConfig struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Description string `yaml:"description"`
}

// KernelConfig contains kernel parameter definitions
type KernelConfig []KernelParameter

// KernelParameter defines a kernel security parameter
type KernelParameter struct {
	Parameter   string   `yaml:"parameter"`
	Expected    string   `yaml:"expected"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	References  []string `yaml:"references"`
	Exploitable bool     `yaml:"exploitable"`
}

// ServicesConfig contains service security settings
type ServicesConfig struct {
	ProhibitedServices []ServiceRule `yaml:"prohibited_services"`
	RequiredServices   []ServiceRule `yaml:"required_services"`
}

// ServiceRule defines service security rules
type ServiceRule struct {
	Name        string `yaml:"name"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
	Exploitable bool   `yaml:"exploitable"`
}

// SSHConfig contains SSH security configuration
type SSHConfig struct {
	ConfigFile string         `yaml:"config_file"`
	Parameters []SSHParameter `yaml:"parameters"`
}

// SSHParameter defines SSH security parameters
type SSHParameter struct {
	Parameter   string `yaml:"parameter"`
	Expected    string `yaml:"expected"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
	Exploitable bool   `yaml:"exploitable"`
}

// FilesystemConfig contains filesystem security settings
type FilesystemConfig struct {
	SecureMounts         map[string]MountSecurity `yaml:"secure_mounts"`
	DangerousFilesystems []string                 `yaml:"dangerous_filesystems"`
}

// MountSecurity defines mount point security requirements
type MountSecurity struct {
	RequiredOptions []string `yaml:"required_options"`
	Severity        string   `yaml:"severity"`
}

// OutputConfig contains output formatting settings
type OutputConfig struct {
	DefaultFormat       string `yaml:"default_format"`
	IncludePassed       bool   `yaml:"include_passed"`
	ShowExploitableOnly bool   `yaml:"show_exploitable_only"`
	ColorOutput         bool   `yaml:"color_output"` // Kept for report.go, though logger is simplified
	VerboseRemediation  bool   `yaml:"verbose_remediation"`
}

// ScanningConfig contains scanning behavior settings
type ScanningConfig struct {
	StealthMode      bool `yaml:"stealth_mode"`
	AdvancedAnalysis bool `yaml:"advanced_analysis"`
	DeepScan         bool `yaml:"deep_scan"`
	SkipHarmless     bool `yaml:"skip_harmless"`
}

// ThreatConfig contains threat assessment settings
type ThreatConfig struct {
	CalculateScores         bool `yaml:"calculate_scores"`
	IncludeAttackVectors    bool `yaml:"include_attack_vectors"`
	GenerateRemediationPlan bool `yaml:"generate_remediation_plan"`
	AssessExploitability    bool `yaml:"assess_exploitability"`
}

// ModulesConfig contains scan module enable/disable settings
type ModulesConfig struct {
	Kernel      bool `yaml:"kernel"`
	Services    bool `yaml:"services"`
	SSH         bool `yaml:"ssh"`
	Filesystem  bool `yaml:"filesystem"`
	Network     bool `yaml:"network"`
	Users       bool `yaml:"users"`
	Permissions bool `yaml:"permissions"`
	SUID        bool `yaml:"suid"`
	Packages    bool `yaml:"packages"`
	Logs        bool `yaml:"logs"`
	Firewall    bool `yaml:"firewall"`
	SELinux     bool `yaml:"selinux"`
	Cron        bool `yaml:"cron"`
	Boot        bool `yaml:"boot"`
}

// ReportingConfig contains reporting settings
type ReportingConfig struct {
	IncludeSystemInfo   bool `yaml:"include_system_info"`
	ShowBanner          bool `yaml:"show_banner"`
	ExecutiveSummary    bool `yaml:"executive_summary"`
	TechnicalDetails    bool `yaml:"technical_details"`
	RemediationPriority bool `yaml:"remediation_priority"`
}

// LoadConfig loads configuration from file or returns default config
func LoadConfig(configFile string) (*Config, error) {
	if configFile == "" {
		configFile = findConfigFile()
	}
	if configFile == "" {
		return getDefaultConfig(), nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", configFile, err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", configFile, err)
	}

	mergeDefaults(&config)
	return &config, nil
}

// findConfigFile looks for config file in standard locations
func findConfigFile() string {
	locations := []string{
		"./config.yaml",
		"./configs/config.yaml",
		"~/.hardend/config.yaml",
		"/etc/hardend/config.yaml",
	}

	for _, location := range locations {
		if location[0] == '~' {
			if home, err := os.UserHomeDir(); err == nil {
				location = filepath.Join(home, location[1:])
			}
		}
		if _, err := os.Stat(location); err == nil {
			return location
		}
	}
	return ""
}

// getDefaultConfig returns the default configuration
func getDefaultConfig() *Config {
	return &Config{
		Application: ApplicationConfig{
			Name:        "hardend",
			Version:     "2.0.0",
			Description: "Linux Security Hardening Assessment Tool",
		},
		Output: OutputConfig{
			DefaultFormat:       "table",
			IncludePassed:       false,
			ShowExploitableOnly: false,
			ColorOutput:         true,
			VerboseRemediation:  true,
		},
		Scanning: ScanningConfig{
			StealthMode:      false,
			AdvancedAnalysis: true,
			DeepScan:         true,
			SkipHarmless:     false,
		},
		Threat: ThreatConfig{
			CalculateScores:         true,
			IncludeAttackVectors:    true,
			GenerateRemediationPlan: true,
			AssessExploitability:    true,
		},
		Modules: ModulesConfig{
			Kernel:     true,
			Services:   true,
			SSH:        true,
			Filesystem: true,
			// ... all others default to false ...
		},
		Reporting: ReportingConfig{
			IncludeSystemInfo:   true,
			ShowBanner:          true,
			ExecutiveSummary:    true,
			TechnicalDetails:    true,
			RemediationPriority: true,
		},
	}
}

// mergeDefaults fills in any missing configuration values with defaults
func mergeDefaults(config *Config) {
	defaults := getDefaultConfig()
	if config.Application.Name == "" {
		config.Application = defaults.Application
	}
	if config.Output.DefaultFormat == "" {
		config.Output = defaults.Output
	}
	// ... add other merges as needed ...
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	validFormats := []string{"table", "json", "html"}
	valid := false
	for _, format := range validFormats {
		if c.Output.DefaultFormat == format {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid output format: %s", c.Output.DefaultFormat)
	}
	return nil
}

// IsModuleEnabled checks if a scan module is enabled
func (c *Config) IsModuleEnabled(module string) bool {
	switch module {
	case "kernel":
		return c.Modules.Kernel
	case "services":
		return c.Modules.Services
	case "ssh":
		return c.Modules.SSH
	case "filesystem":
		return c.Modules.Filesystem
	// ... all other modules ...
	default:
		return false
	}
}

// GetEnabledModules returns a list of enabled scan modules
func (c *Config) GetEnabledModules() []string {
	var enabled []string
	modules := map[string]bool{
		"kernel":      c.Modules.Kernel,
		"services":    c.Modules.Services,
		"ssh":         c.Modules.SSH,
		"filesystem":  c.Modules.Filesystem,
		"network":     c.Modules.Network,
		"users":       c.Modules.Users,
		"permissions": c.Modules.Permissions,
		"suid":        c.Modules.SUID,
		"packages":    c.Modules.Packages,
		"logs":        c.Modules.Logs,
		"firewall":    c.Modules.Firewall,
		"selinux":     c.Modules.SELinux,
		"cron":        c.Modules.Cron,
		"boot":        c.Modules.Boot,
	}
	for module, isEnabled := range modules {
		if isEnabled {
			enabled = append(enabled, module)
		}
	}
	return enabled
}
