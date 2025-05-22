package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// logPrintln is a wrapper for fmt.Println that prefixes with "[Permiso] "
func logPrintln(a ...interface{}) {
	args := []interface{}{"[Permiso]"}
	args = append(args, a...)
	fmt.Println(args...)
}

// logPrintf is a wrapper for fmt.Printf that prefixes with "[Permiso] "
func logPrintf(format string, a ...interface{}) {
	fmt.Printf("[Permiso] "+format, a...)
}

// logErrorf is a wrapper for fmt.Fprintf(os.Stderr) that prefixes with "[Permiso] "
func logErrorf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "[Permiso] "+format, a...)
}

// printBanner displays a welcome banner with information about the tool
func printBanner() {
	fmt.Println("====================================================================")
	fmt.Println("Running permiso-ad-scanner-container")
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

	// Default output directory where RustHound-CE stores its files
	outputDir := "/app/output"

	// Check for output directory in rusthound args
	for i := 0; i < len(argsToPass)-1; i++ {
		if argsToPass[i] == "-o" || argsToPass[i] == "--outdir" {
			outputDir = argsToPass[i+1]
			break
		}
	}

	// Filter out -z or --zip arguments
	filteredArgs := make([]string, 0, len(argsToPass))
	for i := 0; i < len(argsToPass); i++ {
		// Skip -z or --zip
		if argsToPass[i] == "-z" || argsToPass[i] == "--zip" {
			logPrintf("INFO: Removing %s argument from rusthound command, compression is handled by permiso-ad-scanner-container\n", argsToPass[i])
			continue
		}

		filteredArgs = append(filteredArgs, argsToPass[i])
	}
	argsToPass = filteredArgs

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		logErrorf("Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	// Run prerequisite checks if not skipped
	if !*skipPrerequisites {
		checksPassed := runPrerequisiteChecks(argsToPass, outputDir, *minDiskSpace, *maxMemory)
		if !checksPassed {
			logErrorf("\nOne or more prerequisite checks failed. Fix the issues or use --skip-checks to bypass.\n")
			os.Exit(1)
		}
	}

	// Prepare the command to run RustHound-CE with all provided arguments
	cmd := exec.Command("/app/rusthound-ce")

	// Pass the filtered arguments to RustHound-CE
	if len(argsToPass) > 0 {
		cmd.Args = append(cmd.Args, argsToPass...)
	}

	// Set up the command to use the same standard input, output, and error as this program
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Execute RustHound-CE in the background so we can monitor it
	logPrintln("\nExecuting RustHound-CE with arguments:", strings.Join(argsToPass, " "))

	// Resource monitoring information
	if *monitoringEnabled {
		logPrintln("Resource monitoring enabled:")
		logPrintf("- Minimum disk space: %d MB\n", *minDiskSpace)
		logPrintf("- Maximum memory usage: %d MB\n", *maxMemory)
		logPrintf("- Check interval: %d seconds\n", *checkInterval)
	}

	// Start the process
	err := cmd.Start()
	if err != nil {
		logErrorf("Error starting RustHound-CE: %v\n", err)
		os.Exit(1)
	}

	// Get the process ID for monitoring
	pid := cmd.Process.Pid
	logPrintf("RustHound-CE started with PID: %d\n", pid)
	logErrorf("DEBUG: Process details - PID: %d, Process: %+v\n", pid, cmd.Process)

	// Set up resource monitoring if enabled
	var monitor *ResourceMonitor
	if *monitoringEnabled {
		monitor = NewResourceMonitor(*minDiskSpace, *maxMemory, *checkInterval, outputDir, cmd.Process, *debugMode)
		monitor.StartMonitoring()
	}

	// Wait for the command to complete
	logErrorf("DEBUG: Waiting for process to complete...\n")
	err = cmd.Wait()
	logErrorf("DEBUG: Process Wait() completed with error: %v\n", err)

	// Stop monitoring
	if *monitoringEnabled && monitor != nil {
		logErrorf("DEBUG: Stopping resource monitor\n")
		monitor.Stop()
	}

	// Check if process was terminated due to resource constraints
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			logErrorf("RustHound-CE exited with an error: %v\n", err)
		} else {
			logErrorf("Error executing RustHound-CE: %v\n", err)
			// If the error contains "killed" it was likely terminated by our monitor
			if strings.Contains(err.Error(), "killed") {
				logErrorf("Process was terminated due to resource constraints, exiting wrapper\n")
				os.Exit(1)
			}
		}
	} else {
		logPrintln("\nRustHound-CE completed successfully.")
	}

	// Run post-processing on the output files
	logPrintln("\nPerforming post-processing on generated files...")

	summary, err := ProcessRustHoundOutput(outputDir, *debugMode)
	if err != nil {
		logErrorf("Error during post-processing: %v\n", err)
	} else {
		// Create summary file in the output directory
		summaryPath := filepath.Join(outputDir, "summary.json")
		err = SaveSummaryToFile(summary, summaryPath)
		if err != nil {
			logErrorf("Error saving summary file: %v\n", err)
		} else {
			logPrintf("Summary saved to %s\n", summaryPath)
		}

		// Display summary information
		logPrintln("\nPost-processing results:")
		logPrintf("- Total files processed: %d\n", summary.TotalFiles)
		logPrintf("- Total size: %.2f MB\n", float64(summary.TotalBytes)/(1024*1024))
		logPrintf("- Processing time: %s\n", summary.ProcessingTime)

		logPrintln("\nSecurity findings:")
		for _, finding := range summary.SecurityFindings {
			logPrintf("- %s: %s\n", finding.Type, finding.Description)
		}

		// Print findings summary by category
		categoryCounts := GetCategorySummary(summary.SecurityFindings)
		logPrintln("\nFindings summary by category:")
		if len(categoryCounts) == 0 {
			logPrintln("No security issues found.")
		} else {
			for category, count := range categoryCounts {
				logPrintf("- %s: %d\n", category, count)
			}
			logPrintf("\nTotal security issues found: %d\n", len(summary.SecurityFindings))
		}

		// Compress output files and clean up if enabled
		if *compressOutput {
			logPrintln("\nCompressing output files and cleaning up...")
			err = CompressOutputAndCleanup(outputDir, *debugMode)
			if err != nil {
				logErrorf("Error compressing output files: %v\n", err)
			}
		}
	}

	// List all files generated by RustHound-CE
	logPrintln("\nFiles generated by rusthound-wrapper:")

	fileCount := 0
	totalBytes := int64(0)

	err = filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			relPath, err := filepath.Rel(outputDir, path)
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
		logErrorf("Error listing files: %v\n", err)
		os.Exit(1)
	}

	logPrintf("\nSummary: Generated %d files, total size %d bytes (%.2f MB)\n",
		fileCount, totalBytes, float64(totalBytes)/(1024*1024))
}
