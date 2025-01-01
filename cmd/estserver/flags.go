package main

import (
	"flag"
	"fmt"
	"os/exec"
	"strings"
)

// Global constants.
const (
	appName = "estserver"
)

// Version information
var (
	versionString string
	commit        = "unknown"
	dirty         = false
	tag           = "unknown"
)

// Flag name constants.
const (
	configFlag       = "config"
	helpFlag         = "help"
	sampleConfigFlag = "sampleconfig"
	versionFlag      = "version"
)

// Flags.
var (
	fConfig       = flag.String(configFlag, "", "")
	fHelp         = flag.Bool(helpFlag, false, "")
	fSampleConfig = flag.Bool(sampleConfigFlag, false, "")
	fVersion      = flag.Bool(versionFlag, false, "")
)

func init() {
	initVersionInfo()
}

// initVersionInfo initializes version information from Git
func initVersionInfo() {
	// Get latest tag
	if tagOutput, err := exec.Command("git", "describe", "--tags", "--abbrev=0").Output(); err == nil {
		tag = strings.TrimSpace(string(tagOutput))
	}

	// Get commit hash
	if hash, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output(); err == nil {
		commit = strings.TrimSpace(string(hash))
	}

	// Check if working directory is dirty
	if status, err := exec.Command("git", "status", "--porcelain").Output(); err == nil {
		dirty = len(status) > 0
	}

	// Construct version string
	versionString = fmt.Sprintf("%s (commit: %s%s)",
		tag,
		commit,
		map[bool]string{true: "-dirty", false: ""}[dirty],
	)
}

// usage outputs usage information.
func usage() {
	fmt.Printf("usage: %s [options]\n", appName)
	fmt.Println()
	fmt.Printf("%s is a non-production Enrollment over Secure Transport (EST)\n", appName)
	fmt.Printf("certificate enrollment protocol server for testing and demonstration\n")
	fmt.Printf("purposes. See RFC7030.\n")
	fmt.Println()
	const fw = 16
	fmt.Println("Options:")
	fmt.Printf("    -%-*s path to configuration file\n", fw, configFlag+" <path>")
	fmt.Printf("    -%-*s show this usage information\n", fw, helpFlag)
	fmt.Printf("    -%-*s output a sample configuration file\n", fw, sampleConfigFlag)
	fmt.Printf("    -%-*s show version information\n", fw, versionFlag)
	fmt.Println()
}

// version outputs version information.
func version() {
	fmt.Printf("KRITIS3M ASL EST Server %s\n", versionString)
}
