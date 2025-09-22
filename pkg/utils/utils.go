package utils

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/briandowns/spinner"
)

// IsRoot checks if the current user has root access level
func IsRoot() bool {
	return os.Geteuid() == 0
}

// GetCurrentUser returns the current neural interface user
func GetCurrentUser() (*user.User, error) {
	return user.Current()
}

// ExecuteCommand executes a system command in stealth mode
func ExecuteCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// StealthExecute executes a command without leaving traces
func StealthExecute(name string, args ...string) (string, error) {
	// Clear environment variables that might leave traces
	cmd := exec.Command(name, args...)
	cmd.Env = []string{
		"PATH=/usr/bin:/bin:/sbin:/usr/sbin",
		"TERM=dumb",
		"HOME=/tmp",
	}
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// FileExists checks if a file exists in the matrix
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsExecutable checks if a file has executable neural pathways
func IsExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&0111 != 0
}

// GetSystemInfo returns comprehensive system intelligence
func GetSystemInfo() (string, string, string) {
	hostname, _ := os.Hostname()
	return hostname, runtime.GOOS, runtime.GOARCH
}

// ReadLines reads all lines from a neural data file
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

// TypewriterPrint prints text with cyberpunk typewriter effect
func TypewriterPrint(c *color.Color, text string, delay time.Duration) {
	for _, char := range text {
		c.Printf(string(char))
		time.Sleep(delay)
	}
	c.Println()
}

// ProgressBar displays a cyberpunk progress bar
func ProgressBar(message string, duration time.Duration) {
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	s.Color("cyan")
	s.Prefix = color.New(color.FgCyan).Sprint("◢◤ ")
	s.Suffix = color.New(color.FgCyan).Sprintf(" %s", message)
	s.Start()
	time.Sleep(duration)
	s.Stop()
	color.New(color.FgGreen).Printf("◢◤ %s [COMPLETE]\n", message)
}

// MatrixEffect displays the iconic matrix digital rain
func MatrixEffect(duration time.Duration) {
	color.New(color.FgGreen).Println("\n◢◤ ENTERING THE MATRIX...")

	chars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?")
	width := 80
	height := 20

	// Clear screen
	fmt.Print("\033[2J\033[H")

	start := time.Now()
	for time.Since(start) < duration {
		// Create matrix rain
		for i := 0; i < height; i++ {
			for j := 0; j < width; j++ {
				if rand.Intn(10) < 2 {
					color.New(color.FgGreen).Printf(string(chars[rand.Intn(len(chars))]))
				} else {
					fmt.Print(" ")
				}
			}
			fmt.Println()
		}
		time.Sleep(100 * time.Millisecond)
		fmt.Print("\033[2J\033[H") // Clear screen
	}

	color.New(color.FgCyan, color.Bold).Println("◢◤ MATRIX CONNECTION ESTABLISHED\n")
}

// GlitchText creates cyberpunk text glitch effect
func GlitchText(text string, intensity int) string {
	if intensity <= 0 {
		return text
	}

	glitchChars := []rune("!@#$%^&*(){}[]|\\:;"'<>?")
	runes := []rune(text)

	for i := 0; i < intensity && i < len(runes); i++ {
		pos := rand.Intn(len(runes))
		if runes[pos] != ' ' {
			runes[pos] = glitchChars[rand.Intn(len(glitchChars))]
		}
	}

	return string(runes)
}

// HexDump creates a cyberpunk-style hex dump display
func HexDump(data []byte, address uint64) string {
	var result strings.Builder

	for i := 0; i < len(data); i += 16 {
		// Address
		result.WriteString(color.New(color.FgYellow).Sprintf("%08X  ", address+uint64(i)))

		// Hex bytes
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				result.WriteString(color.New(color.FgCyan).Sprintf("%02X ", data[i+j]))
			} else {
				result.WriteString("   ")
			}
			if j == 7 {
				result.WriteString(" ")
			}
		}

		// ASCII representation
		result.WriteString(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				result.WriteString(color.New(color.FgGreen).Sprintf("%c", b))
			} else {
				result.WriteString(color.New(color.FgRed).Sprint("."))
			}
		}
		result.WriteString("|\n")
	}

	return result.String()
}

// CyberpunkLogger provides themed logging functionality
type CyberpunkLogger struct {
	verbose bool
	stealth bool
}

// NewCyberpunkLogger creates a new themed logger
func NewCyberpunkLogger(verbose, stealth bool) *CyberpunkLogger {
	return &CyberpunkLogger{
		verbose: verbose,
		stealth: stealth,
	}
}

// Info logs information with cyberpunk styling
func (cl *CyberpunkLogger) Info(message string, args ...interface{}) {
	if cl.stealth {
		return
	}
	color.New(color.FgCyan).Printf("◢◤ INFO: "+message+"\n", args...)
}

// Warning logs warnings with cyberpunk styling
func (cl *CyberpunkLogger) Warning(message string, args ...interface{}) {
	if cl.stealth {
		return
	}
	color.New(color.FgYellow, color.Bold).Printf("◢◤ WARNING: "+message+"\n", args...)
}

// Error logs errors with cyberpunk styling
func (cl *CyberpunkLogger) Error(message string, args ...interface{}) {
	color.New(color.FgRed, color.Bold).Printf("◢◤ ERROR: "+message+"\n", args...)
}

// Debug logs debug information if verbose mode is enabled
func (cl *CyberpunkLogger) Debug(message string, args ...interface{}) {
	if cl.verbose && !cl.stealth {
		color.New(color.FgMagenta).Printf("◢◤ DEBUG: "+message+"\n", args...)
	}
}

// Critical logs critical errors with special effects
func (cl *CyberpunkLogger) Critical(message string, args ...interface{}) {
	glitched := GlitchText(fmt.Sprintf(message, args...), 3)
	color.New(color.FgRed, color.Bold, color.BlinkSlow).Printf("◢◤ CRITICAL: %s\n", glitched)
}

// GetNetworkInterfaces returns available network interfaces
func GetNetworkInterfaces() ([]string, error) {
	output, err := ExecuteCommand("ip", "link", "show")
	if err != nil {
		return nil, err
	}

	var interfaces []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, ": ") && !strings.HasPrefix(line, " ") {
			parts := strings.Split(line, ": ")
			if len(parts) >= 2 {
				name := strings.Split(parts[1], "@")[0]
				interfaces = append(interfaces, name)
			}
		}
	}

	return interfaces, nil
}

// CheckProcessRunning checks if a process is running
func CheckProcessRunning(processName string) bool {
	output, err := ExecuteCommand("pgrep", processName)
	return err == nil && strings.TrimSpace(output) != ""
}

// GetSystemLoad returns current system load
func GetSystemLoad() (string, error) {
	return ExecuteCommand("uptime")
}

// ScanOpenPorts performs a basic port scan
func ScanOpenPorts(host string, ports []int) map[int]bool {
	result := make(map[int]bool)

	for _, port := range ports {
		output, err := ExecuteCommand("timeout", "1", "bash", "-c",
			fmt.Sprintf("echo >/dev/tcp/%s/%d", host, port))
		result[port] = err == nil && strings.TrimSpace(output) == ""
	}

	return result
}
