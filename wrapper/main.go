package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Global log file
var (
	logFile     *os.File
	logFilePath string
	logMutex    sync.Mutex
)

// initLogFile creates a log file in the output directory
func initLogFile(outputDir string) error {
	// Create timestamp for log file name
	timestamp := time.Now().Format("20060102_150405")
	logFilePath = filepath.Join(outputDir, fmt.Sprintf("permiso_ad_scanner_%s.log", timestamp))

	// Create the log file
	var err error
	logFile, err = os.Create(logFilePath)
	if err != nil {
		return fmt.Errorf("failed to create log file: %v", err)
	}

	// Log initial message
	fmt.Fprintf(logFile, "Permiso AD Scanner Log - Started at %s\n", time.Now().Format("2006-01-02 15:04:05"))
	return nil
}

// closeLogFile closes the log file
func closeLogFile() {
	if logFile != nil {
		logFile.Close()
	}
}

// logPrintln is a wrapper for fmt.Println that prefixes with "[Permiso] " and also logs to file
func logPrintln(a ...interface{}) {
	logMutex.Lock()
	defer logMutex.Unlock()

	args := []interface{}{"[Permiso]"}
	args = append(args, a...)
	fmt.Println(args...)

	// Also log to file if available
	if logFile != nil {
		fmt.Fprintln(logFile, args...)
	}
}

// logPrintf is a wrapper for fmt.Printf that prefixes with "[Permiso] " and also logs to file
func logPrintf(format string, a ...interface{}) {
	logMutex.Lock()
	defer logMutex.Unlock()

	fmt.Printf("[Permiso] "+format, a...)

	// Also log to file if available
	if logFile != nil {
		fmt.Fprintf(logFile, "[Permiso] "+format, a...)
	}
}

// logErrorf is a wrapper for fmt.Fprintf(os.Stderr) that prefixes with "[Permiso] " and also logs to file
func logErrorf(format string, a ...interface{}) {
	logMutex.Lock()
	defer logMutex.Unlock()

	fmt.Fprintf(os.Stderr, "[Permiso] "+format, a...)

	// Also log to file if available
	if logFile != nil {
		fmt.Fprintf(logFile, "[Permiso] "+format, a...)
	}
}

// printBanner displays a welcome banner with information about the tool
func printBanner() {
	fmt.Println("====================================================================")
	fmt.Println("Running permiso-ad-scanner")
	fmt.Println("")
	fmt.Println("Initial version of Permiso's AD scanner. It will collect diagnostics")
	fmt.Println("using the Rusthound open source utility, and machine/OS/network")
	fmt.Println("diagnostics to enable a fully deployed AD scanner.")
	fmt.Println("=====================================================================")
}

// printHelp displays the usage information for both the wrapper and RustHound-CE
func printHelp() {
	// Keep the help output clean without the prefix
	fmt.Println("rusthound-wrapper - some description")
	fmt.Println("")
	fmt.Println("WRAPPER OPTIONS:")
	fmt.Println("  --min-disk <MB>        Minimum disk space in MB before terminating (default: 500)")
	fmt.Println("  --max-memory <MB>      Maximum memory usage in MB before terminating (default: 2048)")
	fmt.Println("  --check-interval <sec> Resource check interval in seconds (default: 1)")
	fmt.Println("  --monitor              Enable resource monitoring (default: true)")
	fmt.Println("  --skip-checks          Skip prerequisite checks (default: false)")
	fmt.Println("  --debug                Enable debug logging (default: false)")
	fmt.Println("  --help                 Display this help message")
	fmt.Println("  --                     Separator for wrapper and RustHound-CE options")
	fmt.Println("")
	fmt.Println("RUSTHOUND-CE OPTIONS:")
	fmt.Println("  -v...                  Set the level of verbosity")
	fmt.Println("  -h, --help             Print RustHound-CE help")
	fmt.Println("  -V, --version          Print version")
	fmt.Println("")
	fmt.Println("REQUIRED VALUES:")
	fmt.Println("  -d, --domain <domain>  Domain name like: DOMAIN.LOCAL")
	fmt.Println("")
	fmt.Println("OPTIONAL VALUES:")
	fmt.Println("  -u, --ldapusername <ldapusername>  LDAP username, like: user@domain.local")
	fmt.Println("  -p, --ldappassword <ldappassword>  LDAP password")
	fmt.Println("  -f, --ldapfqdn <ldapfqdn>          Domain Controller FQDN like: DC01.DOMAIN.LOCAL or just DC01")
	fmt.Println("  -i, --ldapip <ldapip>              Domain Controller IP address like: 192.168.1.10")
	fmt.Println("  -P, --ldapport <ldapport>          LDAP port [default: 389]")
	fmt.Println("  -n, --name-server <name-server>    Alternative IP address name server to use for DNS queries")
	fmt.Println("  -o, --output <o>                   Output directory where you would like to save JSON files [default: ./]")
	fmt.Println("")
	fmt.Println("OPTIONAL FLAGS:")
	fmt.Println("  -c, --collectionmethod [<COLLECTIONMETHOD>]")
	fmt.Println("          Which information to collect. Supported: All (LDAP,SMB,HTTP requests), DCOnly (no computer connections, only LDAP requests)")
	fmt.Println("          [possible values: All, DCOnly]")
	fmt.Println("      --ldaps             Force LDAPS using for request like: ldaps://DOMAIN.LOCAL/")
	fmt.Println("  -k, --kerberos          Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME)")
	fmt.Println("      --dns-tcp           Use TCP instead of UDP for DNS queries")
	fmt.Println("")
	fmt.Println("OPTIONAL MODULES:")
	fmt.Println("      --fqdn-resolver     Use fqdn-resolver module to get computers IP address")
	fmt.Println("")
	fmt.Println("EXAMPLES:")
	fmt.Println("  rusthound-wrapper --min-disk 1000 --max-memory 4096 -- -d domain.local -u user@domain.local -p password")
	fmt.Println("  rusthound-wrapper -- -d domain.local -u user@domain.local -p password -o /app/output")
	fmt.Println("")
	fmt.Println("OUTPUT DETAILS:")
	fmt.Println("  - Security findings will be summarized and saved to summary.json")
	fmt.Println("  - all files except summary.json will be compressed into a zip archive")
	fmt.Println("  - Category summaries for security findings are displayed after processing")
}

// printSuccessBanner displays a banner for successful execution
func printSuccessBanner(execDir string) {
	// Get list of important files
	zipFile := ""
	findingsFile := ""
	logFileName := ""

	// Find the ZIP, summary, and log files
	files, err := os.ReadDir(execDir)
	if err == nil {
		for _, file := range files {
			name := file.Name()
			if strings.HasPrefix(name, "permiso_ad_scanner_results_") && strings.HasSuffix(name, ".zip") {
				zipFile = name
			} else if name == "permiso_security_findings.json" {
				findingsFile = name
			} else if strings.HasPrefix(name, "permiso_ad_scanner_") && strings.HasSuffix(name, ".log") {
				logFileName = name
			}
		}
	}

	fmt.Println("")
	fmt.Println("====================================================================")
	fmt.Println("Successfully finished permiso-ad-scanner")
	fmt.Println("")
	fmt.Println("Files generated:")
	if zipFile != "" {
		fmt.Printf("  - %s\n", zipFile)
	}
	if findingsFile != "" {
		fmt.Printf("  - %s\n", findingsFile)
	}
	if logFileName != "" {
		fmt.Printf("  - %s\n", logFileName)
	}
	fmt.Println("")
	fmt.Println("Please send the zip file securely to Permiso support. This will be")
	fmt.Println("sent to Permiso's threat research team and engineering team to build")
	fmt.Println("detections and an Active Directory application that can run on a")
	fmt.Println("full and regular basis.")
	fmt.Println("=====================================================================")

	// Also log to file if available
	if logFile != nil {
		fmt.Fprintln(logFile, "")
		fmt.Fprintln(logFile, "====================================================================")
		fmt.Fprintln(logFile, "Successfully finished permiso-ad-scanner")
		fmt.Fprintln(logFile, "")
		fmt.Fprintln(logFile, "Files generated:")
		if zipFile != "" {
			fmt.Fprintf(logFile, "  - %s\n", zipFile)
		}
		if findingsFile != "" {
			fmt.Fprintf(logFile, "  - %s\n", findingsFile)
		}
		if logFileName != "" {
			fmt.Fprintf(logFile, "  - %s\n", logFileName)
		}
		fmt.Fprintln(logFile, "")
		fmt.Fprintln(logFile, "Please send the zip file securely to Permiso support. This will be")
		fmt.Fprintln(logFile, "sent to Permiso's threat research team and engineering team to build")
		fmt.Fprintln(logFile, "detections and an Active Directory application that can run on a")
		fmt.Fprintln(logFile, "full and regular basis.")
		fmt.Fprintln(logFile, "=====================================================================")
	}
}

// printErrorBanner displays a banner for execution with errors
func printErrorBanner(execDir string) {
	// Get list of important files
	zipFile := ""
	findingsFile := ""
	logFileName := ""

	// Find the ZIP, summary, and log files
	files, err := os.ReadDir(execDir)
	if err == nil {
		for _, file := range files {
			name := file.Name()
			if strings.HasPrefix(name, "permiso_ad_scanner_results_") && strings.HasSuffix(name, ".zip") {
				zipFile = name
			} else if name == "permiso_security_findings.json" {
				findingsFile = name
			} else if strings.HasPrefix(name, "permiso_ad_scanner_") && strings.HasSuffix(name, ".log") {
				logFileName = name
			}
		}
	}

	fmt.Println("")
	fmt.Println("====================================================================")
	fmt.Println("Permiso AD Scanner completed with ERRORS!")
	fmt.Println("")
	fmt.Println("Files generated:")
	if zipFile != "" {
		fmt.Printf("  - %s\n", zipFile)
	}
	if findingsFile != "" {
		fmt.Printf("  - %s\n", findingsFile)
	}
	if logFileName != "" {
		fmt.Printf("  - %s\n", logFileName)
	}
	fmt.Println("")
	fmt.Println("Please send the zip file securely to Permiso support. The file contains")
	fmt.Println("execution logs that will help our threat research and engineering")
	fmt.Println("teams troubleshoot issues.")
	fmt.Println("=====================================================================")

	// Also log to file if available
	if logFile != nil {
		fmt.Fprintln(logFile, "")
		fmt.Fprintln(logFile, "====================================================================")
		fmt.Fprintln(logFile, "Permiso AD Scanner completed with ERRORS!")
		fmt.Fprintln(logFile, "")
		fmt.Fprintln(logFile, "Files generated:")
		if zipFile != "" {
			fmt.Fprintf(logFile, "  - %s\n", zipFile)
		}
		if findingsFile != "" {
			fmt.Fprintf(logFile, "  - %s\n", findingsFile)
		}
		if logFileName != "" {
			fmt.Fprintf(logFile, "  - %s\n", logFileName)
		}
		fmt.Fprintln(logFile, "")
		fmt.Fprintln(logFile, "Please send the zip file securely to Permiso support. The file contains")
		fmt.Fprintln(logFile, "execution logs that will help our threat research and engineering")
		fmt.Fprintln(logFile, "teams troubleshoot issues.")
		fmt.Fprintln(logFile, "=====================================================================")
	}
}

// sanitizeArgs removes sensitive information like passwords from command line arguments
func sanitizeArgs(args []string) []string {
	sanitized := make([]string, len(args))
	copy(sanitized, args)

	// Check for password parameters
	for i, arg := range sanitized {
		// Handle format: -p password or --ldappassword password
		if (arg == "-p" || arg == "--ldappassword") && i+1 < len(sanitized) {
			sanitized[i+1] = "[REDACTED]"
		}

		// Handle format: -p=password or --ldappassword=password
		if strings.HasPrefix(arg, "-p=") || strings.HasPrefix(arg, "--ldappassword=") {
			parts := strings.SplitN(arg, "=", 2)
			sanitized[i] = parts[0] + "=[REDACTED]"
		}
	}

	return sanitized
}

// detectErrorsInOutput checks if the output contains error messages
func detectErrorsInOutput(output string) bool {
	errorPatterns := []string{
		"[ERROR rusthound_ce",
		"ERROR rusthound_ce",
		"Failed to authenticate",
		"Error:",
		"error:",
		"Fatal:",
		"fatal:",
		"Operation failed",
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(output, pattern) {
			return true
		}
	}

	return false
}

// createExecutionDirectory creates a timestamped subdirectory for this execution
func createExecutionDirectory(baseDir string) (string, error) {
	// Create timestamp for directory name
	timestamp := time.Now().Format("20060102_150405")
	execDir := filepath.Join(baseDir, fmt.Sprintf("scan_%s", timestamp))

	// Create the directory
	if err := os.MkdirAll(execDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create execution directory: %v", err)
	}

	return execDir, nil
}

func main() {
	// Display the banner
	printBanner()

	// Check for "help" command first
	if len(os.Args) > 1 && (os.Args[1] == "help" || os.Args[1] == "--help" || os.Args[1] == "-h") {
		printHelp()
		return
	}

	// Find the index of "--" if present
	delimiterIndex := -1
	for i, arg := range os.Args {
		if arg == "--" {
			delimiterIndex = i
			break
		}
	}

	// Setup a custom FlagSet for our wrapper flags
	wrapperFlags := flag.NewFlagSet("wrapper", flag.ExitOnError)
	wrapperFlags.Usage = printHelp

	// Define flags for resource monitoring
	minDiskSpace := wrapperFlags.Uint64("min-disk", 500, "Minimum disk space in MB before terminating")
	maxMemory := wrapperFlags.Uint64("max-memory", 2048, "Maximum memory usage in MB before terminating")
	checkInterval := wrapperFlags.Int("check-interval", 1, "Resource check interval in seconds")
	monitoringEnabled := wrapperFlags.Bool("monitor", true, "Enable resource monitoring")
	skipPrerequisites := wrapperFlags.Bool("skip-checks", false, "Skip prerequisite checks")
	debugMode := wrapperFlags.Bool("debug", false, "Enable debug logging")
	compressOutput := wrapperFlags.Bool("compress", true, "Compress output files into a zip archive and clean up originals")

	// Process arguments
	var argsToPass []string
	if delimiterIndex == -1 {
		// No delimiter, try to parse all arguments as wrapper flags
		// Any unknown flags will fail
		if err := wrapperFlags.Parse(os.Args[1:]); err != nil {
			// If parsing fails, assume all args are for RustHound-CE
			argsToPass = os.Args[1:]
		} else {
			// Successfully parsed all flags
			// Everything after the parsed flags should go to RustHound-CE
			argsToPass = wrapperFlags.Args()
		}
	} else {
		// Delimiter found, parse only the wrapper flags before the delimiter
		if delimiterIndex > 1 {
			if err := wrapperFlags.Parse(os.Args[1:delimiterIndex]); err != nil {
				logErrorf("Error parsing wrapper flags: %v\n", err)
				wrapperFlags.Usage()
				os.Exit(1)
			}
		}
		// Everything after the delimiter goes to RustHound-CE
		if delimiterIndex < len(os.Args)-1 {
			argsToPass = os.Args[delimiterIndex+1:]
		}
	}

	// Default base output directory where we'll create our execution subdirectory
	baseOutputDir := "/app/output"

	// Check for output directory in rusthound args
	outputDirSpecified := false
	for i := 0; i < len(argsToPass)-1; i++ {
		if argsToPass[i] == "-o" || argsToPass[i] == "--outdir" {
			baseOutputDir = argsToPass[i+1]
			outputDirSpecified = true
			break
		}
	}

	// Ensure base output directory exists
	if err := os.MkdirAll(baseOutputDir, 0755); err != nil {
		logErrorf("Error creating base output directory: %v\n", err)
		os.Exit(1)
	}

	// Create a timestamped execution directory for this run
	execDir, err := createExecutionDirectory(baseOutputDir)
	if err != nil {
		logErrorf("Error creating execution directory: %v\n", err)
		os.Exit(1)
	}

	// If the user specified an output directory, we need to update the args to use our execution directory
	if outputDirSpecified {
		for i := 0; i < len(argsToPass)-1; i++ {
			if argsToPass[i] == "-o" || argsToPass[i] == "--outdir" {
				argsToPass[i+1] = execDir
				break
			}
		}
	} else {
		// If no output directory was specified, add it to the arguments
		argsToPass = append(argsToPass, "-o", execDir)
	}

	// Initialize log file in the execution directory
	if err := initLogFile(execDir); err != nil {
		logErrorf("Failed to initialize log file: %v\n", err)
		// Continue without file logging
	} else {
		defer closeLogFile()
	}

	// Log the execution directory
	logPrintf("Created execution directory: %s\n", execDir)

	// Filter out -z or --zip arguments
	filteredArgs := make([]string, 0, len(argsToPass))
	for i := 0; i < len(argsToPass); i++ {
		// Skip -z or --zip
		if argsToPass[i] == "-z" || argsToPass[i] == "--zip" {
			logPrintf("INFO: Removing %s argument from rusthound command, compression is handled by permiso-ad-scanner\n", argsToPass[i])
			continue
		}

		filteredArgs = append(filteredArgs, argsToPass[i])
	}
	argsToPass = filteredArgs

	// Run prerequisite checks if not skipped
	if !*skipPrerequisites {
		checksPassed := runPrerequisiteChecks(argsToPass, execDir, *minDiskSpace, *maxMemory)
		if !checksPassed {
			fmt.Println("")
			logErrorf("One or more prerequisite checks failed. Fix the issues or use --skip-checks to bypass.\n")
			printErrorBanner(execDir)
			os.Exit(1)
		}
	}

	// Prepare the command to run RustHound-CE with all provided arguments
	cmd := exec.Command("/app/rusthound-ce")

	// Pass the filtered arguments to RustHound-CE
	if len(argsToPass) > 0 {
		cmd.Args = append(cmd.Args, argsToPass...)
	}

	// Create a pipe for capturing stderr while still showing it to the user
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		logErrorf("Error creating stderr pipe: %v\n", err)
		printErrorBanner(execDir)
		os.Exit(1)
	}

	// Create a pipe for capturing stdout while still showing it to the user
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		logErrorf("Error creating stdout pipe: %v\n", err)
		printErrorBanner(execDir)
		os.Exit(1)
	}

	// Set up the command to use the user's standard input
	cmd.Stdin = os.Stdin

	// Track if we detect error messages in the output
	errorDetected := false

	// Execute RustHound-CE in the background so we can monitor it
	fmt.Println("")
	logPrintln("Executing RustHound-CE with arguments:", strings.Join(sanitizeArgs(argsToPass), " "))

	// Resource monitoring information
	if *monitoringEnabled {
		logPrintln("Resource monitoring enabled:")
		logPrintf("- Minimum disk space: %d MB\n", *minDiskSpace)
		logPrintf("- Maximum memory usage: %d MB\n", *maxMemory)
		logPrintf("- Check interval: %d seconds\n", *checkInterval)
	}

	// Start the process
	err = cmd.Start()
	if err != nil {
		logErrorf("Error starting RustHound-CE: %v\n", err)
		printErrorBanner(execDir)
		os.Exit(1)
	}

	// Get the process ID for monitoring
	pid := cmd.Process.Pid
	logPrintf("RustHound-CE started with PID: %d\n", pid)
	if *debugMode {
		logErrorf("DEBUG: Process details - PID: %d, Process: %+v\n", pid, cmd.Process)
	}

	// Set up resource monitoring if enabled
	var monitor *ResourceMonitor
	if *monitoringEnabled {
		monitor = NewResourceMonitor(*minDiskSpace, *maxMemory, *checkInterval, execDir, cmd.Process, *debugMode)
		monitor.StartMonitoring()
	}

	// Start a goroutine to read stderr and detect errors
	var stderrBuffer bytes.Buffer
	go func() {
		tee := io.TeeReader(stderrPipe, os.Stderr)
		io.Copy(&stderrBuffer, tee)
	}()

	// Start a goroutine to read stdout
	var stdoutBuffer bytes.Buffer
	go func() {
		tee := io.TeeReader(stdoutPipe, os.Stdout)
		io.Copy(&stdoutBuffer, tee)
	}()

	// Wait for the command to complete
	if *debugMode {
		logErrorf("DEBUG: Waiting for process to complete...\n")
	}
	err = cmd.Wait()
	if err != nil {
		logErrorf("DEBUG: Process Wait() completed with error: %v\n", err)
	}

	// Stop monitoring
	if *monitoringEnabled && monitor != nil {
		if *debugMode {
			logErrorf("DEBUG: Stopping resource monitor\n")
		}
		monitor.Stop()
	}

	// Check for error patterns in the captured stderr
	stderrOutput := stderrBuffer.String()
	stdoutOutput := stdoutBuffer.String()
	if detectErrorsInOutput(stderrOutput) || detectErrorsInOutput(stdoutOutput) {
		errorDetected = true
		logErrorf("Detected error messages in the RustHound-CE output\n")
	}

	// Track overall success/failure
	hasErrors := false

	// Check if process was terminated due to resource constraints
	if err != nil {
		hasErrors = true
		if _, ok := err.(*exec.ExitError); ok {
			fmt.Println("")
			logErrorf("RustHound-CE exited with an error: %v\n", err)
		} else {
			fmt.Println("")
			logErrorf("Error executing RustHound-CE: %v\n", err)
			// If the error contains "killed" it was likely terminated by our monitor
			if strings.Contains(err.Error(), "killed") {
				fmt.Println("")
				logErrorf("Process was terminated due to resource constraints, exiting wrapper\n")
				printErrorBanner(execDir)
				os.Exit(1)
			}
		}
	} else {
		// Even if the process completed with a zero exit code, check if we detected errors in the output
		if errorDetected {
			hasErrors = true
			fmt.Println("")
			logErrorf("RustHound-CE completed with error messages in output\n")
		} else {
			fmt.Println("")
			logPrintln("RustHound-CE completed successfully.")
		}
	}

	if hasErrors {
		fmt.Println("")
		logPrintln("RustHound-CE completed with errors, performing post-processing on partial results...")
	} else {
		fmt.Println("")
		logPrintln("Performing post-processing on generated files...")
	}

	summary, err := ProcessRustHoundOutput(execDir, *debugMode)
	if err != nil {
		hasErrors = true
		logErrorf("Error during post-processing: %v\n", err)
	} else {
		// Create summary file in the execution directory
		summaryPath := filepath.Join(execDir, "permiso_security_findings.json")
		err = SaveSummaryToFile(summary, summaryPath)
		if err != nil {
			hasErrors = true
			logErrorf("Error saving summary file: %v\n", err)
		} else {
			logPrintf("Summary saved to %s\n", summaryPath)
		}

		// Display summary information
		fmt.Println("")
		logPrintln("Post-processing results:")
		logPrintf("- Total files processed: %d\n", summary.TotalFiles)
		logPrintf("- Total size: %.2f MB\n", float64(summary.TotalBytes)/(1024*1024))
		logPrintf("- Processing time: %s\n", summary.ProcessingTime)

		fmt.Println("")
		// Print findings summary by category
		categoryCounts := GetCategorySummary(summary.SecurityFindings)
		fmt.Println("")
		logPrintln("Security findings summary:")
		if len(categoryCounts) == 0 {
			logPrintln("No security issues found.")
		} else {
			for category, count := range categoryCounts {
				logPrintf("- %s: %d\n", category, count)
			}
			fmt.Println("")
			logPrintf("Total security issues found: %d\n", len(summary.SecurityFindings))
		}

		// Compress output files and clean up if enabled
		if *compressOutput {
			fmt.Println("")
			logPrintln("Compressing output files and cleaning up...")
			err = CompressOutputAndCleanup(execDir, *debugMode)
			if err != nil {
				hasErrors = true
				logErrorf("Error compressing output files: %v\n", err)
			}
		}
	}

	// List all files generated in this execution directory only
	fmt.Println("")
	logPrintf("Files generated in this execution (%s):\n", filepath.Base(execDir))

	fileCount := 0
	totalBytes := int64(0)

	err = filepath.Walk(execDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			relPath, err := filepath.Rel(execDir, path)
			if err != nil {
				relPath = path
			}
			logPrintf("- %s (%d bytes)\n", relPath, info.Size())
			fileCount++
			totalBytes += info.Size()
		}
		return nil
	})

	if err != nil {
		hasErrors = true
		logErrorf("Error listing files: %v\n", err)
		printErrorBanner(execDir)
		os.Exit(1)
	}

	fmt.Println("")
	logPrintf("Summary: Generated %d files, total size %d bytes (%.2f MB)\n",
		fileCount, totalBytes, float64(totalBytes)/(1024*1024))
	logPrintf("Execution directory: %s\n", execDir)

	// Print success or error banner based on the result
	if !hasErrors {
		printSuccessBanner(execDir)
	} else {
		printErrorBanner(execDir)
	}
}
