package main

import (
	"flag"
	"os"
	"strings"
	"time"

	"github.com/ConstantineCTF/hardend/pkg/checks"
	"github.com/ConstantineCTF/hardend/pkg/config"
	"github.com/ConstantineCTF/hardend/pkg/report"
	"github.com/ConstantineCTF/hardend/pkg/utils"
	"github.com/fatih/color"
)

const (
	appName    = "hardend"
	appVersion = "2077.1.0"
	appDesc    = "◢◤ CYBERSEC NEURAL INTERFACE ◢◤ Linux System Penetration Assessment Framework"
)

type Options struct {
	ConfigFile   string
	OutputFormat string
	OutputFile   string
	Verbose      bool
	Quiet        bool
	Stealth      bool
	CheckTypes   []string
	ShowVersion  bool
	ShowHelp     bool
	Matrix       bool
	GhostMode    bool
}

func main() {
	printCyberpunkBanner()
	opts := parseArgs()

	if opts.ShowVersion {
		printVersionInfo()
		os.Exit(0)
	}

	if opts.ShowHelp {
		showCyberpunkHelp()
		os.Exit(0)
	}

	// Initialize neural interface
	if !opts.Quiet {
		utils.TypewriterPrint(color.New(color.FgCyan), "◢◤ INITIALIZING NEURAL INTERFACE", 30*time.Millisecond)
		utils.ProgressBar("Loading security protocols", 2*time.Second)
	}

	// Check access level
	if !utils.IsRoot() && !opts.Quiet {
		color.New(color.FgYellow, color.Bold).Println("⚠ WARNING: Limited access detected - some neural pathways restricted")
		color.New(color.FgRed).Println("  └─ For full system penetration, escalate privileges")
	}

	// Matrix mode activation
	if opts.Matrix {
		utils.MatrixEffect(3 * time.Second)
	}

	// Load configuration matrix
	cfg, err := config.LoadConfig(opts.ConfigFile)
	if err != nil {
		color.New(color.FgRed, color.Bold).Printf("◢◤ FATAL ERROR: Neural interface corrupted: %v\n", err)
		os.Exit(1)
	}

	// Initialize penetration framework
	runner := checks.NewRunner(cfg, opts.Verbose, opts.Stealth, opts.GhostMode)

	// Execute security scan
	if !opts.Quiet {
		color.New(color.FgGreen, color.Bold).Println("◢◤ ENGAGING SECURITY SCAN PROTOCOLS")
		utils.TypewriterPrint(color.New(color.FgCyan), "   └─ Scanning for vulnerabilities in the matrix...", 20*time.Millisecond)
	}

	results, err := runPenetrationScan(runner, opts.CheckTypes, opts.Stealth)
	if err != nil {
		color.New(color.FgRed, color.Bold).Printf("◢◤ SCAN FAILURE: %v\n", err)
		os.Exit(1)
	}

	// Generate assessment report
	reporter := report.NewCyberpunkReporter(opts.OutputFormat, opts.Quiet)
	if err := reporter.Generate(results, opts.OutputFile); err != nil {
		color.New(color.FgRed, color.Bold).Printf("◢◤ REPORT GENERATION FAILED: %v\n", err)
		os.Exit(1)
	}

	// Final status
	if !opts.Quiet {
		printScanComplete(results)
	}

	// Exit with appropriate neural response code
	if results.HasCriticalVulnerabilities() {
		if !opts.Quiet {
			color.New(color.FgRed, color.Bold).Println("◢◤ CRITICAL VULNERABILITIES DETECTED - SYSTEM COMPROMISED")
		}
		os.Exit(13) // Unlucky for attackers
	}

	if !opts.Quiet {
		color.New(color.FgGreen, color.Bold).Println("◢◤ NEURAL INTERFACE DISCONNECTED - STAY VIGILANT, SAMURAI")
	}
}

func parseArgs() *Options {
	opts := &Options{}

	flag.StringVar(&opts.ConfigFile, "config", "", "Neural configuration matrix file")
	flag.StringVar(&opts.OutputFormat, "format", "cyberpunk", "Output format (cyberpunk, matrix, json, html)")
	flag.StringVar(&opts.OutputFile, "output", "", "Output file path (default: neural stdout)")
	flag.BoolVar(&opts.Verbose, "verbose", false, "Enable verbose neural logging")
	flag.BoolVar(&opts.Quiet, "quiet", false, "Silent running mode")
	flag.BoolVar(&opts.Stealth, "stealth", false, "Stealth scan mode (reduces detection)")
	flag.BoolVar(&opts.Matrix, "matrix", false, "Enable matrix visual effects")
	flag.BoolVar(&opts.GhostMode, "ghost", false, "Ghost in the shell mode")
	flag.BoolVar(&opts.ShowVersion, "version", false, "Show neural interface version")
	flag.BoolVar(&opts.ShowHelp, "help", false, "Access help database")

	checkTypesStr := flag.String("scans", "all", "Comma-separated scan modules (neural,ice,daemon,net)")

	flag.Parse()

	if *checkTypesStr != "" {
		opts.CheckTypes = strings.Split(*checkTypesStr, ",")
	}

	return opts
}

func printCyberpunkBanner() {
	banner := `
    ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗██████╗ 
    ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║██╔══██╗
    ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║██║  ██║
    ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║██║  ██║
    ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║██████╔╝
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═════╝ 

    ◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤
    ▓▓▓ CYBERSEC NEURAL INTERFACE v2077.1.0 ▓▓▓
    ▓▓▓ "The future is now, samurai" - Johnny ▓▓▓  
    ◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤
`
	color.New(color.FgCyan, color.Bold).Print(banner)
	time.Sleep(500 * time.Millisecond)
}

func printVersionInfo() {
	color.New(color.FgCyan, color.Bold).Printf("%s v%s\n", appName, appVersion)
	color.New(color.FgYellow).Printf("%s\n", appDesc)
	color.New(color.FgGreen).Printf("◢◤ Neural Architecture: %s/%s\n", os.Getenv("GOOS"), os.Getenv("GOARCH"))
	color.New(color.FgMagenta).Printf("◢◤ Compiled with: Go quantum compiler\n")
	color.New(color.FgRed).Printf("◢◤ Warning: Unauthorized access will be traced and flatlined\n")
}

func runPenetrationScan(runner *checks.Runner, checkTypes []string, stealth bool) (*checks.Results, error) {
	if len(checkTypes) == 1 && checkTypes[0] == "all" {
		return runner.RunFullPenetrationSuite()
	}
	return runner.RunSelectedScans(checkTypes, stealth)
}

func printScanComplete(results *checks.Results) {
	color.New(color.FgGreen, color.Bold).Println("\n◢◤ PENETRATION SCAN COMPLETE")
	color.New(color.FgCyan).Printf("   └─ System: %s\n", results.SystemInfo.Hostname)
	color.New(color.FgCyan).Printf("   └─ Duration: %s\n", results.Duration)
	color.New(color.FgCyan).Printf("   └─ Vulnerabilities Found: %d\n", len(results.Findings))

	if results.Summary.CriticalIssues > 0 {
		color.New(color.FgRed, color.Bold).Printf("   └─ Critical Exploits: %d\n", results.Summary.CriticalIssues)
	}
}

func showCyberpunkHelp() {
	help := `
◢◤ HARDEND NEURAL INTERFACE HELP DATABASE ◢◤

USAGE:
  hardend [NEURAL_OPTIONS]

NEURAL OPTIONS:
  -scans string      Comma-separated scan modules (default "all")
  -config string     Neural configuration matrix file  
  -format string     Output format (cyberpunk, matrix, json, html) (default "cyberpunk")
  -output string     Output file path (default: neural stdout)
  -verbose           Enable verbose neural logging
  -quiet             Silent running mode
  -stealth           Stealth scan mode (reduces detection)
  -matrix            Enable matrix visual effects
  -ghost             Ghost in the shell mode
  -version           Show neural interface version  
  -help              Access this help database

AVAILABLE SCAN MODULES:
  neural      ◢◤ Kernel neural pathways & memory protection
  ice         ◢◤ Intrusion countermeasures & services  
  daemon      ◢◤ Background daemon analysis
  net         ◢◤ Network interface penetration
  ghost       ◢◤ SSH ghost protocol analysis
  users       ◢◤ User account breach vectors
  perms       ◢◤ File permission vulnerabilities
  suid        ◢◤ Privilege escalation vectors
  packages    ◢◤ Software vulnerability database
  logs        ◢◤ Audit trail forensics
  firewall    ◢◤ Network barrier analysis
  selinux     ◢◤ Mandatory access control bypass
  cron        ◢◤ Scheduled task exploitation
  boot        ◢◤ System boot hijack vectors
  all         ◢◤ Full penetration test suite (default)

EXAMPLE NEURAL COMMANDS:
  hardend                           # Full system penetration
  hardend -scans neural,ghost       # Kernel and SSH analysis only  
  hardend -format matrix -output hack.json
  hardend -stealth -ghost -quiet    # Silent ghost mode
  hardend -matrix -verbose          # Matrix mode with full logging

◢◤ Remember samurai: "Never fade away" ◢◤
`
	color.New(color.FgCyan).Print(help)
}
