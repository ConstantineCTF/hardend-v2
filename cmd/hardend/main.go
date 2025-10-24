package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ConstantineCTF/hardend/pkg/checks"
	"github.com/ConstantineCTF/hardend/pkg/config"
	"github.com/ConstantineCTF/hardend/pkg/report"
	"github.com/ConstantineCTF/hardend/pkg/utils"
)

const (
	appName    = "hardend"
	appVersion = "2.0.0" // Updated version
	appDesc    = "A professional Linux security hardening assessment framework."
)

// Options holds the command-line flags
type Options struct {
	ConfigFile   string
	OutputFormat string
	OutputFile   string
	Verbose      bool
	Quiet        bool
	Stealth      bool
	CheckTypes   []string
	ShowVersion  bool
}

func main() {
	// Use standard log flags
	log.SetFlags(log.LstdFlags)

	opts := parseArgs()

	if opts.ShowVersion {
		fmt.Printf("%s v%s\n%s\n", appName, appVersion, appDesc)
		os.Exit(0)
	}

	// Initialize logger
	if opts.Quiet {
		log.SetOutput(os.Stderr) // Point to stderr or ioutil.Discard if truly silent
	}

	log.Println("Initializing security assessment...")

	// Check access level
	if !utils.IsRoot() && !opts.Quiet {
		log.Println("WARNING: Running as non-root. Some checks may be skipped or return incomplete results.")
	}

	// Load configuration
	cfg, err := config.LoadConfig(opts.ConfigFile)
	if err != nil {
		log.Fatalf("FATAL: Failed to load configuration: %v\n", err)
	}

	// Initialize assessment framework
	// Note: 'GhostMode' (from main.go) seems unused in the provided files, so it's removed.
	runner := checks.NewRunner(cfg, opts.Verbose, opts.Stealth)

	// Execute security scan
	if !opts.Quiet {
		log.Println("Starting security assessment scans...")
	}

	results, err := runAssessmentScan(runner, opts.CheckTypes, opts.Stealth)
	if err != nil {
		log.Fatalf("SCAN FAILURE: %v\n", err)
	}

	// Generate assessment report
	reporter := report.NewReporter(opts.OutputFormat, opts.Quiet)
	if err := reporter.Generate(results, opts.OutputFile); err != nil {
		log.Fatalf("REPORT GENERATION FAILED: %v\n", err)
	}

	// Final status
	if !opts.Quiet {
		printScanComplete(results)
	}

	// Exit with standard code 1 on critical findings
	if results.HasCriticalVulnerabilities() {
		if !opts.Quiet {
			log.Println("CRITICAL VULNERABILITIES DETECTED. Review report for details.")
		}
		os.Exit(1)
	}

	if !opts.Quiet {
		log.Println("Security assessment complete.")
	}
}

// parseArgs parses command-line flags
func parseArgs() *Options {
	opts := &Options{}

	// Use standard flag names
	flag.StringVar(&opts.ConfigFile, "config", "configs/config.yaml", "Path to the configuration file.")
	flag.StringVar(&opts.OutputFormat, "format", "table", "Output format (table, json, html).")
	flag.StringVar(&opts.OutputFile, "output", "", "Output file path (default: stdout).")
	flag.BoolVar(&opts.Verbose, "verbose", false, "Enable verbose logging.")
	flag.BoolVar(&opts.Quiet, "quiet", false, "Silent mode (suppress stdout).")
	flag.BoolVar(&opts.Stealth, "stealth", false, "Stealth scan mode (reduces noise).")
	flag.BoolVar(&opts.ShowVersion, "version", false, "Show application version.")

	// Professional names for scan modules
	checkTypesStr := flag.String("scans", "all", "Comma-separated scan modules (e.g., kernel,services,ssh,filesystem).")

	// Standard help text
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", appName)
		fmt.Fprintf(os.Stderr, "%s [options]\n\n", appDesc)
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nAvailable Scan Modules:\n")
		fmt.Fprintf(os.Stderr, "  kernel, services, ssh, filesystem, network, users, perms, suid, packages, logs, firewall, selinux, cron, boot, all\n")
	}

	flag.Parse()

	if *checkTypesStr != "" {
		opts.CheckTypes = strings.Split(*checkTypesStr, ",")
	}

	return opts
}

// runAssessmentScan determines which scans to run
func runAssessmentScan(runner *checks.Runner, checkTypes []string, stealth bool) (*checks.Results, error) {
	if len(checkTypes) == 1 && checkTypes[0] == "all" {
		log.Println("Running full assessment suite...")
		return runner.RunFullPenetrationSuite() // Assuming this function exists in runner.go
	}
	log.Printf("Running selected scans: %v", checkTypes)
	return runner.RunSelectedScans(checkTypes, stealth) // Assuming this function exists
}

// printScanComplete logs the final summary
func printScanComplete(results *checks.Results) {
	log.Println("--- ASSESSMENT COMPLETE ---")
	log.Printf("  Target System: %s", results.SystemInfo.Hostname)
	log.Printf("  Scan Duration: %s", results.Duration)
	log.Printf("  Total Findings: %d", len(results.Findings))
	if results.Summary.CriticalIssues > 0 {
		log.Printf("  CRITICAL ISSUES: %d", results.Summary.CriticalIssues)
	}
	if results.Summary.HighIssues > 0 {
		log.Printf("  High Issues: %d", results.Summary.HighIssues)
	}
}
