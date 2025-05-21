package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// printHelp displays the usage information for both the wrapper and RustHound-CE
func printHelp() {
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
				fmt.Fprintf(os.Stderr, "Error parsing wrapper flags: %v\n", err)
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
	outputDir := "./output"

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
			fmt.Fprintf(os.Stderr, "INFO: Removing %s argument from rusthound command\n", argsToPass[i])
			continue
		}

		filteredArgs = append(filteredArgs, argsToPass[i])
	}
	argsToPass = filteredArgs

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	// Run prerequisite checks if not skipped
	if !*skipPrerequisites {
		checksPassed := runPrerequisiteChecks(argsToPass, outputDir, *minDiskSpace, *maxMemory)
		if !checksPassed {
			fmt.Fprintf(os.Stderr, "\nOne or more prerequisite checks failed. Fix the issues or use --skip-checks to bypass.\n")
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
	fmt.Println("\nExecuting RustHound-CE with arguments:", strings.Join(argsToPass, " "))

	// Resource monitoring information
	if *monitoringEnabled {
		fmt.Printf("Resource monitoring enabled:\n")
		fmt.Printf("- Minimum disk space: %d MB\n", *minDiskSpace)
		fmt.Printf("- Maximum memory usage: %d MB\n", *maxMemory)
		fmt.Printf("- Check interval: %d seconds\n", *checkInterval)
	}

	// Start the process
	err := cmd.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting RustHound-CE: %v\n", err)
		os.Exit(1)
	}

	// Get the process ID for monitoring
	pid := cmd.Process.Pid
	fmt.Printf("RustHound-CE started with PID: %d\n", pid)
	fmt.Fprintf(os.Stderr, "DEBUG: Process details - PID: %d, Process: %+v\n", pid, cmd.Process)

	// Set up resource monitoring if enabled
	var monitor *ResourceMonitor
	if *monitoringEnabled {
		monitor = NewResourceMonitor(*minDiskSpace, *maxMemory, *checkInterval, outputDir, cmd.Process, *debugMode)
		monitor.StartMonitoring()
	}

	// Wait for the command to complete
	fmt.Fprintf(os.Stderr, "DEBUG: Waiting for process to complete...\n")
	err = cmd.Wait()
	fmt.Fprintf(os.Stderr, "DEBUG: Process Wait() completed with error: %v\n", err)

	// Stop monitoring
	if *monitoringEnabled && monitor != nil {
		fmt.Fprintf(os.Stderr, "DEBUG: Stopping resource monitor\n")
		monitor.Stop()
	}

	// Check if process was terminated due to resource constraints
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			fmt.Fprintf(os.Stderr, "RustHound-CE exited with an error: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Error executing RustHound-CE: %v\n", err)
			// If the error contains "killed" it was likely terminated by our monitor
			if strings.Contains(err.Error(), "killed") {
				fmt.Fprintf(os.Stderr, "Process was terminated due to resource constraints, exiting wrapper\n")
				os.Exit(1)
			}
		}
	} else {
		fmt.Println("\nRustHound-CE completed successfully.")
	}

	// Run post-processing on the output files
	fmt.Println("\nPerforming post-processing on generated files...")

	summary, err := ProcessRustHoundOutput(outputDir, *debugMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during post-processing: %v\n", err)
	} else {
		// Create summary file in the output directory
		summaryPath := filepath.Join(outputDir, "summary.json")
		err = SaveSummaryToFile(summary, summaryPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error saving summary file: %v\n", err)
		} else {
			fmt.Printf("Summary saved to %s\n", summaryPath)
		}

		// Display summary information
		fmt.Printf("\nPost-processing results:\n")
		fmt.Printf("- Total files processed: %d\n", summary.TotalFiles)
		fmt.Printf("- Total size: %.2f MB\n", float64(summary.TotalBytes)/(1024*1024))
		fmt.Printf("- Processing time: %s\n", summary.ProcessingTime)

		fmt.Printf("\nSecurity findings:\n")
		for _, finding := range summary.SecurityFindings {
			fmt.Printf("- %s: %s\n", finding.Type, finding.Description)
		}

		// Print findings summary by category
		categoryCounts := GetCategorySummary(summary.SecurityFindings)
		fmt.Printf("\nFindings summary by category:\n")
		if len(categoryCounts) == 0 {
			fmt.Println("No security issues found.")
		} else {
			for category, count := range categoryCounts {
				fmt.Printf("- %s: %d\n", category, count)
			}
			fmt.Printf("\nTotal security issues found: %d\n", len(summary.SecurityFindings))
		}

		// Compress output files and clean up if enabled
		if *compressOutput {
			fmt.Println("\nCompressing output files and cleaning up...")
			err = CompressOutputAndCleanup(outputDir, *debugMode)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error compressing output files: %v\n", err)
			}
		}
	}

	// List all files generated by RustHound-CE
	fmt.Println("\nFiles generated by rusthound-wrapper:")

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
			fmt.Printf("- %s (%d bytes)\n", relPath, info.Size())
			fileCount++
			totalBytes += info.Size()
		}
		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing files: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nSummary: Generated %d files, total size %d bytes (%.2f MB)\n",
		fileCount, totalBytes, float64(totalBytes)/(1024*1024))
}
