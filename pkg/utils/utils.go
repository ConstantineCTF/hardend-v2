package utils

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
)

// Logger provides standard logging functionality
type Logger struct {
	verbose bool
	stealth bool
}

// NewLogger creates a new standard logger
func NewLogger(verbose, stealth bool) *Logger {
	log.SetFlags(log.LstdFlags)
	return &Logger{
		verbose: verbose,
		stealth: stealth,
	}
}

// IsVerbose returns true if the logger is in verbose mode.
// This is the new method to safely check the verbose status.
func (l *Logger) IsVerbose() bool {
	return l.verbose
}

// Info logs standard information
func (l *Logger) Info(message string, args ...interface{}) {
	if l.stealth {
		return
	}
	log.Printf("INFO: "+message+"\n", args...)
}

// Warning logs warnings
func (l *Logger) Warning(message string, args ...interface{}) {
	if l.stealth {
		return
	}
	log.Printf("WARN: "+message+"\n", args...)
}

// Error logs errors
func (l *Logger) Error(message string, args ...interface{}) {
	log.Printf("ERROR: "+message+"\n", args...)
}

// Debug logs debug information if verbose mode is enabled
func (l *Logger) Debug(message string, args ...interface{}) {
	if l.verbose && !l.stealth {
		log.Printf("DEBUG: "+message+"\n", args...)
	}
}

// Critical logs critical errors
func (l *Logger) Critical(message string, args ...interface{}) {
	log.Printf("CRITICAL: "+message+"\n", args...)
}

// --- OS Utilities ---
// (Rest of the file remains the same)
// ...

// IsRoot checks if the current user has root privileges
func IsRoot() bool {
	return os.Geteuid() == 0
}

// GetCurrentUser returns the current user
func GetCurrentUser() (*user.User, error) {
	return user.Current()
}

// ExecuteCommand executes a system command
func ExecuteCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// StealthExecute executes a command with minimal environment to reduce traces
func StealthExecute(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = []string{
		"PATH=/usr/bin:/bin:/sbin:/usr/sbin",
		"TERM=dumb",
		"HOME=/tmp",
	}
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// FileExists checks if a file exists on the filesystem
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsExecutable checks if a file has executable permissions
func IsExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&0111 != 0
}

// GetSystemInfo returns basic OS information
func GetSystemInfo() (string, string, string) {
	hostname, _ := os.Hostname()
	return hostname, runtime.GOOS, runtime.GOARCH
}

// ReadLines reads all lines from a file
func ReadLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// GetKernelVersion returns the current running kernel version
func GetKernelVersion() string {
	if output, err := ExecuteCommand("uname", "-r"); err == nil {
		return strings.TrimSpace(output)
	}
	return "unknown"
}

// CheckProcessRunning checks if a process is running
func CheckProcessRunning(processName string) bool {
	output, err := ExecuteCommand("pgrep", processName)
	return err == nil && strings.TrimSpace(output) != ""
}

// GetSystemLoad returns current system load (from uptime)
func GetSystemLoad() (string, error) {
	return ExecuteCommand("uptime")
}

// ScanOpenPorts performs a basic port scan (Note: very basic)
func ScanOpenPorts(host string, ports []int) map[int]bool {
	result := make(map[int]bool)
	for _, port := range ports {
		// Using bash redirection is generally okay for simple checks, but net.Dial is more robust in Go
		_, err := ExecuteCommand("timeout", "1", "bash", "-c",
			fmt.Sprintf("echo >/dev/tcp/%s/%d", host, port))
		// Check error status and potentially output (though output might not be reliable here)
		result[port] = err == nil // A successful connection usually exits with 0
	}
	return result
}
