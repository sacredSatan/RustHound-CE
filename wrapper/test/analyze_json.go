package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SecurityFinding represents a security issue detected during processing
type SecurityFinding struct {
	Type        string `json:"type"`
	Username    string `json:"username"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	FoundIn     string `json:"found_in"`
}

// Summary holds the overall summary of all processed files
type Summary struct {
	TotalFiles       int               `json:"total_files"`
	TotalBytes       int64             `json:"total_bytes"`
	ProcessingTime   string            `json:"processing_time"`
	SecurityFindings []SecurityFinding `json:"security_findings"`
}

// JsonMeta represents the metadata section in RustHound JSON files
type JsonMeta struct {
	Type       string `json:"type"`
	Count      int    `json:"count"`
	Version    int    `json:"version"`
	MethodName string `json:"methodName"`
}

// JsonFile represents the structure of a RustHound JSON file
type JsonFile struct {
	Meta JsonMeta `json:"meta"`
	Data []any    `json:"data"`
}

// UserProperties represents the Properties section of a user object
type UserProperties struct {
	Name                 string `json:"name"`
	DistinguishedName    string `json:"distinguishedname"`
	Enabled              bool   `json:"enabled"`
	LastLogon            int64  `json:"lastlogon"`
	LastLogonTimestamp   int64  `json:"lastlogontimestamp"`
	PasswordNotRequired  bool   `json:"passwordnotreqd"`
	WhenCreated          int64  `json:"whencreated"`
	PwdLastSet           int64  `json:"pwdlastset"`
	DontReqPreauth       bool   `json:"dontreqpreauth"`
	ServicePrincipalName string `json:"serviceprincipalname"`
}

// ADUser represents a RustHound AD user object with its properties
type ADUser struct {
	ObjectIdentifier string         `json:"ObjectIdentifier"`
	IsDeleted        bool           `json:"IsDeleted"`
	IsACLProtected   bool           `json:"IsACLProtected"`
	Properties       UserProperties `json:"Properties"`
}

// Config holds configuration options for processing
type Config struct {
	DormantDaysThreshold int  // Number of days of inactivity to consider an account dormant
	Debug                bool // Enable debug output
}

func main() {
	// Define command line flags
	jsonFilePath := flag.String("file", "", "Path to RustHound JSON file to analyze")
	dormantDays := flag.Int("dormant", 90, "Number of days of inactivity to consider an account dormant")
	verbose := flag.Bool("v", false, "Enable verbose output")
	outputFile := flag.String("output", "", "Path to save results JSON (optional)")
	flag.Parse()

	if *jsonFilePath == "" {
		fmt.Println("Error: Please specify a JSON file with -file flag")
		flag.Usage()
		os.Exit(1)
	}

	// Check if file exists
	fileInfo, err := os.Stat(*jsonFilePath)
	if err != nil {
		fmt.Printf("Error accessing file %s: %v\n", *jsonFilePath, err)
		os.Exit(1)
	}

	if fileInfo.IsDir() {
		fmt.Printf("Error: %s is a directory, not a file\n", *jsonFilePath)
		os.Exit(1)
	}

	// Create a temporary directory to hold just this file
	tempDir, err := os.MkdirTemp("", "rhcel-test")
	if err != nil {
		fmt.Printf("Error creating temp directory: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tempDir)

	// Copy the file to the temp directory
	targetPath := filepath.Join(tempDir, filepath.Base(*jsonFilePath))
	sourceData, err := os.ReadFile(*jsonFilePath)
	if err != nil {
		fmt.Printf("Error reading source file: %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile(targetPath, sourceData, 0644)
	if err != nil {
		fmt.Printf("Error copying file to temp directory: %v\n", err)
		os.Exit(1)
	}

	// Process the file using the wrapper package
	fmt.Printf("Analyzing file: %s\n", *jsonFilePath)
	fmt.Printf("Using dormant account threshold: %d days\n", *dormantDays)
	fmt.Printf("Using temp directory: %s\n", tempDir)

	// Create a configuration
	config := &Config{
		DormantDaysThreshold: *dormantDays,
		Debug:                *verbose,
	}

	// Process the file
	startTime := time.Now()
	summary, err := processRustHoundOutput(tempDir, config)
	if err != nil {
		fmt.Printf("Error processing file: %v\n", err)
		os.Exit(1)
	}

	// Print the findings
	if len(summary.SecurityFindings) == 0 {
		fmt.Println("No security issues found.")
	} else {
		fmt.Printf("Found %d security issues:\n", len(summary.SecurityFindings))
		for i, finding := range summary.SecurityFindings {
			fmt.Printf("%d) [%s] %s: %s (Severity: %s)\n",
				i+1, finding.Type, finding.Username, finding.Description, finding.Severity)
		}
	}

	// Save results to JSON file if requested
	if *outputFile != "" {
		err = saveSummaryToFile(summary, *outputFile)
		if err != nil {
			fmt.Printf("Error saving results to %s: %v\n", *outputFile, err)
			os.Exit(1)
		}
		fmt.Printf("Results saved to %s\n", *outputFile)
	}

	// Print summary
	processingTime := time.Since(startTime)
	fmt.Printf("\nSummary:\n")
	fmt.Printf("- Files processed: %d\n", summary.TotalFiles)
	fmt.Printf("- Processing time: %s\n", processingTime)
	fmt.Printf("- Security findings: %d\n", len(summary.SecurityFindings))
}

// processRustHoundOutput analyzes all files in the output directory and returns a summary
func processRustHoundOutput(outputDir string, config *Config) (*Summary, error) {
	startTime := time.Now()
	if config.Debug {
		fmt.Printf("DEBUG: Starting post-processing of files in %s\n", outputDir)
		fmt.Printf("DEBUG: Using dormant days threshold: %d days\n", config.DormantDaysThreshold)
	}

	summary := &Summary{
		SecurityFindings: make([]SecurityFinding, 0),
	}

	// Walk through all files in the output directory
	err := filepath.Walk(outputDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only process JSON files
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".json") {
			return nil
		}

		// Read the file
		data, err := os.ReadFile(path)
		if err != nil {
			if config.Debug {
				fmt.Printf("DEBUG: Error reading file %s: %v\n", path, err)
			}
			return nil
		}

		summary.TotalFiles++
		summary.TotalBytes += info.Size()

		// Try to parse JSON
		var jsonFile JsonFile
		err = json.Unmarshal(data, &jsonFile)
		if err != nil {
			if config.Debug {
				fmt.Printf("DEBUG: Error parsing JSON in file %s: %v\n", path, err)
			}
			return nil
		}

		// Extract file type from file name or metadata
		fileType := "unknown"
		if jsonFile.Meta.Type != "" {
			fileType = jsonFile.Meta.Type
		} else {
			// Try to extract type from filename
			parts := strings.Split(info.Name(), "_")
			if len(parts) >= 3 {
				fileNameParts := strings.Split(parts[len(parts)-1], ".")
				if len(fileNameParts) > 0 {
					fileType = fileNameParts[0]
				}
			}
		}

		// Process the file for security detections if it contains user data
		if fileType == "users" || strings.Contains(strings.ToLower(info.Name()), "user") {
			processUsersForSecurityIssues(jsonFile.Data, &summary.SecurityFindings, path, config)
		}

		if config.Debug {
			fmt.Printf("DEBUG: Processed file %s: type=%s, count=%d\n",
				info.Name(), fileType, jsonFile.Meta.Count)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking directory: %v", err)
	}

	// Set processing time
	summary.ProcessingTime = time.Since(startTime).String()

	return summary, nil
}

// processUsersForSecurityIssues analyzes user data for security issues
func processUsersForSecurityIssues(userData []any, findings *[]SecurityFinding, sourcePath string, config *Config) {
	if config.Debug {
		fmt.Printf("DEBUG: Processing %d user objects for security issues\n", len(userData))
		fmt.Printf("DEBUG: Current system time: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	}

	// Get current time for dormant account checks
	now := time.Now()
	dormantThreshold := now.AddDate(0, 0, -config.DormantDaysThreshold)

	if config.Debug {
		fmt.Printf("DEBUG: Dormant threshold: %s\n", dormantThreshold.Format("2006-01-02 15:04:05"))
	}

	enabledCount := 0
	for _, rawUser := range userData {
		// Convert the generic user data to JSON and back to get our structured format
		userBytes, err := json.Marshal(rawUser)
		if err != nil {
			if config.Debug {
				fmt.Printf("DEBUG: Error marshaling user data: %v\n", err)
			}
			continue
		}

		var user ADUser
		if err := json.Unmarshal(userBytes, &user); err != nil {
			if config.Debug {
				fmt.Printf("DEBUG: Error parsing user object: %v\n", err)
			}
			continue
		}

		// Skip processing for disabled accounts
		if !user.Properties.Enabled {
			if config.Debug {
				fmt.Printf("DEBUG: Skipping disabled account: %s\n", user.Properties.Name)
			}
			continue
		}
		enabledCount++

		// Rule 1: Dormant accounts with no activity in past X days
		lastActive := getLastActiveTime(user)

		// Case 1: Account has never logged in (lastlogon = 0)
		if lastActive == 0 {
			if config.Debug {
				fmt.Printf("DEBUG: User %s has never logged in (no lastlogon time)\n", user.Properties.Name)
			}

			*findings = append(*findings, SecurityFinding{
				Type:        "dormant_account",
				Username:    user.Properties.Name,
				Description: "Account has never logged in",
				Severity:    "medium",
				FoundIn:     filepath.Base(sourcePath),
			})
			fmt.Printf("Found dormant account: %s (never logged in)\n", user.Properties.Name)
		} else {
			// Case 2: Account has logged in, check if last activity is before dormant threshold
			// Using direct Unix timestamps
			lastActiveTime := time.Unix(lastActive, 0)
			if config.Debug {
				fmt.Printf("DEBUG: User %s last active: %s (timestamp: %d)\n",
					user.Properties.Name, lastActiveTime.Format("2006-01-02"), lastActive)

				// Compare timestamps
				isPast := lastActiveTime.Before(now)
				isDormant := lastActiveTime.Before(dormantThreshold)
				fmt.Printf("DEBUG: Time comparisons - isPast: %v, isDormant: %v\n", isPast, isDormant)
			}

			// Only consider accounts as dormant if:
			// 1. Their last activity timestamp is in the past (not future)
			// 2. Their last activity is before the dormant threshold
			if lastActiveTime.Before(now) && lastActiveTime.Before(dormantThreshold) {
				*findings = append(*findings, SecurityFinding{
					Type:        "dormant_account",
					Username:    user.Properties.Name,
					Description: fmt.Sprintf("Account inactive since %s (>%d days)", lastActiveTime.Format("2006-01-02"), config.DormantDaysThreshold),
					Severity:    "medium",
					FoundIn:     filepath.Base(sourcePath),
				})
				fmt.Printf("Found dormant account: %s, last active: %s\n",
					user.Properties.Name, lastActiveTime.Format("2006-01-02"))
			} else if lastActiveTime.After(now) && config.Debug {
				fmt.Printf("DEBUG: User %s has a future last active date (clock skew?): %s\n",
					user.Properties.Name, lastActiveTime.Format("2006-01-02"))
			}
		}

		// Rule 2: Guest accounts with password not required
		// Check for "guest" in name and passwordnotreqd flag
		if strings.Contains(strings.ToLower(user.Properties.Name), "guest") && user.Properties.PasswordNotRequired {
			*findings = append(*findings, SecurityFinding{
				Type:        "insecure_guest",
				Username:    user.Properties.Name,
				Description: "Guest account with 'password not required' flag set",
				Severity:    "high",
				FoundIn:     filepath.Base(sourcePath),
			})
			fmt.Printf("Found guest account with no password required: %s\n", user.Properties.Name)
		}

		// Show user account properties in verbose mode
		if config.Debug {
			fmt.Printf("DEBUG: User properties for %s - PasswordNotRequired: %v\n",
				user.Properties.Name, user.Properties.PasswordNotRequired)
		}
	}

	if config.Debug {
		fmt.Printf("DEBUG: Processed %d enabled accounts out of %d total accounts\n", enabledCount, len(userData))
	}
}

// getLastActiveTime returns the most recent activity timestamp from lastlogon and lastlogontimestamp
func getLastActiveTime(user ADUser) int64 {
	if user.Properties.LastLogonTimestamp > user.Properties.LastLogon {
		return user.Properties.LastLogonTimestamp
	}
	return user.Properties.LastLogon
}

// saveSummaryToFile saves the summary to a JSON file
func saveSummaryToFile(summary *Summary, outputPath string) error {
	jsonData, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling summary: %v", err)
	}

	err = os.WriteFile(outputPath, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("error writing summary file: %v", err)
	}

	return nil
}
