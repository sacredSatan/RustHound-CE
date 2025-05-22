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

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		DormantDaysThreshold: 90, // Default to 90 days
		Debug:                false,
	}
}

// ProcessRustHoundOutput analyzes all files in the output directory and returns a summary
func ProcessRustHoundOutput(outputDir string, debug bool) (*Summary, error) {
	config := DefaultConfig()
	config.Debug = debug
	return ProcessRustHoundOutputWithConfig(outputDir, config)
}

// ProcessRustHoundOutputWithConfig analyzes all files with custom configuration
func ProcessRustHoundOutputWithConfig(outputDir string, config *Config) (*Summary, error) {
	startTime := time.Now()
	if config.Debug {
		logPrintf("DEBUG: Starting post-processing of files in %s\n", outputDir)
		logPrintf("DEBUG: Using dormant days threshold: %d days\n", config.DormantDaysThreshold)
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
				logPrintf("DEBUG: Error reading file %s: %v\n", path, err)
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
				logPrintf("DEBUG: Error parsing JSON in file %s: %v\n", path, err)
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
			logPrintf("DEBUG: Processed file %s: type=%s, count=%d\n",
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
		logPrintf("DEBUG: Processing %d user objects for security issues\n", len(userData))
	}

	// Get current time for dormant account checks
	now := time.Now()
	dormantThreshold := now.AddDate(0, 0, -config.DormantDaysThreshold)

	enabledCount := 0
	for _, rawUser := range userData {
		// Convert the generic user data to JSON and back to get our structured format
		userBytes, err := json.Marshal(rawUser)
		if err != nil {
			if config.Debug {
				logPrintf("DEBUG: Error marshaling user data: %v\n", err)
			}
			continue
		}

		var user ADUser
		if err := json.Unmarshal(userBytes, &user); err != nil {
			if config.Debug {
				logPrintf("DEBUG: Error parsing user object: %v\n", err)
			}
			continue
		}

		// Skip processing for disabled accounts
		if !user.Properties.Enabled {
			if config.Debug {
				logPrintf("DEBUG: Skipping disabled account: %s\n", user.Properties.Name)
			}
			continue
		}
		enabledCount++

		// Rule 1: Dormant accounts with no activity in past X days
		lastActive := getLastActiveTime(user)

		// Case 1: Account has never logged in (lastlogon = 0)
		if lastActive == 0 {
			if config.Debug {
				logPrintf("DEBUG: User %s has never logged in (no lastlogon time)\n", user.Properties.Name)
			}

			*findings = append(*findings, SecurityFinding{
				Type:        "dormant_account",
				Username:    user.Properties.Name,
				Description: "Account has never logged in",
				Severity:    "medium",
				FoundIn:     filepath.Base(sourcePath),
			})
			if config.Debug {
				logPrintf("DEBUG: Found dormant account: %s (never logged in)\n", user.Properties.Name)
			}
		} else {
			// Case 2: Account has logged in, check if last activity is before dormant threshold
			// Using direct Unix timestamps
			lastActiveTime := time.Unix(lastActive, 0)

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
				if config.Debug {
					logPrintf("DEBUG: Found dormant account: %s, last active: %s (timestamp: %d)\n",
						user.Properties.Name, lastActiveTime.Format("2006-01-02"), lastActive)
				}
			} else if lastActiveTime.After(now) && config.Debug {
				logPrintf("DEBUG: User %s has a future last active date (clock skew?): %s\n",
					user.Properties.Name, lastActiveTime.Format("2006-01-02"))
			}
		}
	}

	if config.Debug {
		logPrintf("DEBUG: Processed %d enabled accounts out of %d total accounts\n", enabledCount, len(userData))
	}
}

// getLastActiveTime returns the most recent activity timestamp from lastlogon and lastlogontimestamp
func getLastActiveTime(user ADUser) int64 {
	if user.Properties.LastLogonTimestamp > user.Properties.LastLogon {
		return user.Properties.LastLogonTimestamp
	}
	return user.Properties.LastLogon
}

// GetCategorySummary returns a map with counts of findings by category
func GetCategorySummary(findings []SecurityFinding) map[string]int {
	categoryCounts := make(map[string]int)

	for _, finding := range findings {
		categoryCounts[finding.Type]++
	}

	return categoryCounts
}

// SaveSummaryToFile saves the summary to a JSON file
func SaveSummaryToFile(summary *Summary, outputPath string) error {
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

// CompressOutputAndCleanup compresses all files in the output directory into a zip file
// and removes the original files, keeping only the permiso_security_findings.json file and log file
func CompressOutputAndCleanup(outputDir string, debug bool) error {
	if debug {
		logPrintf("DEBUG: Compressing output files in %s\n", outputDir)
	}

	// Create timestamp for the archive name
	timestamp := time.Now().Format("20060102_150405")
	archiveName := filepath.Join(outputDir, fmt.Sprintf("permiso_ad_scanner_results_%s.zip", timestamp))

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
				logPrintf("DEBUG: Error reading file for compression %s: %v\n", path, err)
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
				logPrintf("DEBUG: Error creating zip entry for %s: %v\n", relPath, err)
			}
			return nil
		}

		// Write file content to zip
		_, err = zipEntry.Write(data)
		if err != nil {
			if debug {
				logPrintf("DEBUG: Error writing zip entry for %s: %v\n", relPath, err)
			}
			return nil
		}

		if debug {
			logPrintf("DEBUG: Added file to archive: %s\n", relPath)
		}

		// Add to list of files to remove, but keep summary.json and the log file
		baseName := filepath.Base(path)
		if baseName != "permiso_security_findings.json" && !strings.Contains(baseName, "permiso_ad_scanner_") {
			filesToRemove = append(filesToRemove, path)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("error walking directory for compression: %v", err)
	}

	// Make sure we include the current log file (which may still be open)
	if logFile != nil && logFilePath != "" {
		// Create a copy of the log file to include in the zip
		relPath, err := filepath.Rel(outputDir, logFilePath)
		if err != nil {
			relPath = filepath.Base(logFilePath)
		}

		// Sync the log file to ensure all data is written
		logFile.Sync()

		// Read the log file
		data, err := os.ReadFile(logFilePath)
		if err != nil {
			if debug {
				logPrintf("DEBUG: Error reading log file for compression: %v\n", err)
			}
		} else {
			// Create zip entry for the log file
			zipEntry, err := zipWriter.Create(relPath)
			if err != nil {
				if debug {
					logPrintf("DEBUG: Error creating zip entry for log file: %v\n", err)
				}
			} else {
				// Write log file content to zip
				_, err = zipEntry.Write(data)
				if err != nil {
					if debug {
						logPrintf("DEBUG: Error writing log file to zip: %v\n", err)
					}
				} else if debug {
					logPrintf("DEBUG: Added log file to archive: %s\n", relPath)
				}
			}
		}
	}

	// Close the zip writer before removing files
	zipWriter.Close()

	// Remove the original files (except security findings and log file)
	for _, fileToRemove := range filesToRemove {
		err := os.Remove(fileToRemove)
		if err != nil {
			if debug {
				logPrintf("DEBUG: Error removing file %s: %v\n", fileToRemove, err)
			}
		} else if debug {
			logPrintf("DEBUG: Removed original file: %s\n", fileToRemove)
		}
	}

	logPrintf("Archive created: %s\n", archiveName)
	// logPrintf("Original files removed, keeping only permiso_security_findings.json, log file, and archive\n")

	return nil
}
