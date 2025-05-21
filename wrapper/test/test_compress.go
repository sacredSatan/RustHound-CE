package main

import (
	"archive/zip"
	"encoding/json"
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
	// Check if arguments are provided
	var outputDir string
	if len(os.Args) > 1 {
		outputDir = os.Args[1]
	} else {
		outputDir = "../output"
	}
	debug := true

	// Check if output directory exists
	_, err := os.Stat(outputDir)
	if os.IsNotExist(err) {
		fmt.Printf("Output directory %s does not exist\n", outputDir)
		os.Exit(1)
	}

	// Process the output directory
	fmt.Printf("Processing output directory: %s\n", outputDir)
	summary, err := processRustHoundOutput(outputDir, debug)
	if err != nil {
		fmt.Printf("Error during processing: %v\n", err)
		os.Exit(1)
	}

	// Print findings summary
	fmt.Printf("Found %d security issues\n", len(summary.SecurityFindings))
	for i, finding := range summary.SecurityFindings {
		fmt.Printf("%d) [%s] %s: %s (Severity: %s)\n",
			i+1, finding.Type, finding.Username, finding.Description, finding.Severity)
	}

	// Create summary file
	summaryPath := filepath.Join(outputDir, "summary.json")
	err = saveSummaryToFile(summary, summaryPath)
	if err != nil {
		fmt.Printf("Error saving summary: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Summary saved to: %s\n", summaryPath)

	// Compress the output
	fmt.Println("\nCompressing output files and cleaning up...")
	err = compressOutputAndCleanup(outputDir, debug)
	if err != nil {
		fmt.Printf("Error compressing output: %v\n", err)
		os.Exit(1)
	}

	// List files after compression
	fmt.Println("\nFiles after compression:")
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
		}
		return nil
	})
	if err != nil {
		fmt.Printf("Error listing files: %v\n", err)
		os.Exit(1)
	}
}

// processRustHoundOutput analyzes all files in the output directory and returns a summary
func processRustHoundOutput(outputDir string, debug bool) (*Summary, error) {
	startTime := time.Now()
	if debug {
		fmt.Printf("DEBUG: Starting post-processing of files in %s\n", outputDir)
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
			if debug {
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
			if debug {
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
			processUsersForSecurityIssues(jsonFile.Data, &summary.SecurityFindings, path, debug)
		}

		if debug {
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
func processUsersForSecurityIssues(userData []any, findings *[]SecurityFinding, sourcePath string, debug bool) {
	if debug {
		fmt.Printf("DEBUG: Processing %d user objects for security issues\n", len(userData))
	}

	// Get current time for dormant account checks
	now := time.Now()
	dormantThreshold := now.AddDate(0, 0, -90) // 90-day dormant threshold

	enabledCount := 0
	for _, rawUser := range userData {
		// Convert the generic user data to JSON and back to get our structured format
		userBytes, err := json.Marshal(rawUser)
		if err != nil {
			if debug {
				fmt.Printf("DEBUG: Error marshaling user data: %v\n", err)
			}
			continue
		}

		var user ADUser
		if err := json.Unmarshal(userBytes, &user); err != nil {
			if debug {
				fmt.Printf("DEBUG: Error parsing user object: %v\n", err)
			}
			continue
		}

		// Skip processing for disabled accounts
		if !user.Properties.Enabled {
			if debug {
				fmt.Printf("DEBUG: Skipping disabled account: %s\n", user.Properties.Name)
			}
			continue
		}
		enabledCount++

		// Rule 1: Dormant accounts with no activity in past X days
		lastActive := getLastActiveTime(user)

		// Case 1: Account has never logged in (lastlogon = 0)
		if lastActive == 0 {
			if debug {
				fmt.Printf("DEBUG: User %s has never logged in (no lastlogon time)\n", user.Properties.Name)
			}

			*findings = append(*findings, SecurityFinding{
				Type:        "dormant_account",
				Username:    user.Properties.Name,
				Description: "Account has never logged in",
				Severity:    "medium",
				FoundIn:     filepath.Base(sourcePath),
			})
		} else {
			// Case 2: Account has logged in, check if last activity is before dormant threshold
			lastActiveTime := time.Unix(lastActive, 0)

			// Only consider accounts as dormant if:
			// 1. Their last activity timestamp is in the past (not future)
			// 2. Their last activity is before the dormant threshold
			if lastActiveTime.Before(now) && lastActiveTime.Before(dormantThreshold) {
				*findings = append(*findings, SecurityFinding{
					Type:        "dormant_account",
					Username:    user.Properties.Name,
					Description: fmt.Sprintf("Account inactive since %s (>90 days)", lastActiveTime.Format("2006-01-02")),
					Severity:    "medium",
					FoundIn:     filepath.Base(sourcePath),
				})
			}
		}

		// Rule 2: Guest accounts with password not required
		if strings.Contains(strings.ToLower(user.Properties.Name), "guest") && user.Properties.PasswordNotRequired {
			*findings = append(*findings, SecurityFinding{
				Type:        "insecure_guest",
				Username:    user.Properties.Name,
				Description: "Guest account with 'password not required' flag set",
				Severity:    "high",
				FoundIn:     filepath.Base(sourcePath),
			})
		}
	}

	if debug {
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

// compressOutputAndCleanup compresses all files in the output directory into a zip file
// and removes the original files, keeping only the summary.json file
func compressOutputAndCleanup(outputDir string, debug bool) error {
	if debug {
		fmt.Printf("DEBUG: Compressing output files in %s\n", outputDir)
	}

	// Create timestamp for the archive name
	timestamp := time.Now().Format("20060102_150405")
	archiveName := filepath.Join(outputDir, fmt.Sprintf("rusthound_results_%s.zip", timestamp))

	// Create zip archive
	zipFile, err := os.Create(archiveName)
	if err != nil {
		return fmt.Errorf("error creating zip file: %v", err)
	}
	defer zipFile.Close()

	// Create zip writer
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Collect list of files to remove after compression
	filesToRemove := []string{}

	// Walk through all files in the output directory
	err = filepath.Walk(outputDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Skip the archive itself
		if path == archiveName {
			return nil
		}

		// Read file to be compressed
		data, err := os.ReadFile(path)
		if err != nil {
			if debug {
				fmt.Printf("DEBUG: Error reading file for compression %s: %v\n", path, err)
			}
			return nil
		}

		// Get relative path for zip entry
		relPath, err := filepath.Rel(outputDir, path)
		if err != nil {
			relPath = filepath.Base(path)
		}

		// Create zip entry
		zipEntry, err := zipWriter.Create(relPath)
		if err != nil {
			if debug {
				fmt.Printf("DEBUG: Error creating zip entry for %s: %v\n", relPath, err)
			}
			return nil
		}

		// Write file content to zip
		_, err = zipEntry.Write(data)
		if err != nil {
			if debug {
				fmt.Printf("DEBUG: Error writing zip entry for %s: %v\n", relPath, err)
			}
			return nil
		}

		if debug {
			fmt.Printf("DEBUG: Added file to archive: %s\n", relPath)
		}

		// Add to list of files to remove, but keep summary.json
		if filepath.Base(path) != "summary.json" {
			filesToRemove = append(filesToRemove, path)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("error walking directory for compression: %v", err)
	}

	// Close the zip writer before removing files
	zipWriter.Close()

	// Remove the original files (except summary.json)
	for _, fileToRemove := range filesToRemove {
		err := os.Remove(fileToRemove)
		if err != nil {
			if debug {
				fmt.Printf("DEBUG: Error removing file %s: %v\n", fileToRemove, err)
			}
		} else if debug {
			fmt.Printf("DEBUG: Removed original file: %s\n", fileToRemove)
		}
	}

	fmt.Printf("Archive created: %s\n", archiveName)
	fmt.Printf("Original files removed, keeping only summary.json and archive\n")

	return nil
}
