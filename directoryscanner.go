// Package directoryscanner provides simple directory scanning functionality
// for sensitive data
package directoryscanner

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
)

var compiledRegexes = map[string][]*regexp.Regexp{
	"Credit Card":   {regexp.MustCompile("^(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})$")},
	"SSN":           {regexp.MustCompile("(^\\d{3}-?\\d{2}-?\\d{4}$|^XXX-XX-XXXX$)")},
	"Word Password": {regexp.MustCompile("password")},
	"Word Username": {regexp.MustCompile("username")},
	"Email":         {regexp.MustCompile("^[\\w\\.=-]+@[\\w\\.-]+\\.[\\w]{2,3}$")},
}

// will hold results from the scan
var resultsScan []string
var selectedTypes []string
var mu sync.Mutex

func scanFiles(path string, info os.FileInfo, err error) error {

	file, err := os.Open(path)
	fscanner := bufio.NewScanner(file)
	lineNumber := 1
	var resultsString string
	// skip the source code
	if file.Name() != "directory_scanner.go" {
		for fscanner.Scan() {
			for key, cr := range compiledRegexes {
				for _, r := range cr {
					if found := r.Find([]byte(fscanner.Text())); found != nil {
						resultsString = key + `,` + string(found) + `,` + file.Name() + `,` + strconv.Itoa(lineNumber)
						resultsScan = append(resultsScan, resultsString)

					}
				}
			}
			lineNumber++
		}
	}
	return err
}

func findSpecific(path string, info os.FileInfo, err error) error {

	file, err := os.Open(path)
	fscanner := bufio.NewScanner(file)
	lineNumber := 1
	var resultsString string
	// skip the source code
	if file.Name() != "directory_scanner.go" {
		for fscanner.Scan() {
			for _, dataType := range selectedTypes {
				for key, cr := range compiledRegexes {
					if dataType == key {
						for _, r := range cr {
							if found := r.Find([]byte(fscanner.Text())); found != nil {
								resultsString = key + `,` + string(found) + `,` + file.Name() + `,` + strconv.Itoa(lineNumber)
								resultsScan = append(resultsScan, resultsString)
							}
						}
					} else {
						continue
					}
				}
			}
			lineNumber++
		}
	}

	return err
}

// Scan ...
// begins at the specified path (path) and recursively searches all directories
func Scan(path string) ([]string, error) {
	mu.Lock()
	defer mu.Unlock()
	resultsScan = nil
	err := filepath.Walk(path, scanFiles)
	if err != nil {
		return nil, err
	}
	return resultsScan, nil
}

// Find ...
// begins at the specified path (path) and recursively searches all directories
// acceptable arguments for variatic function: "Credit Card", "SSN", "Word Password", "Word Username", "Email"
func Find(path string, dataTypes ...string) ([]string, error) {
	mu.Lock()
	defer mu.Unlock()
	resultsScan = nil
	selectedTypes = nil
	selectedTypes = append(selectedTypes, dataTypes...)
	err := filepath.Walk(path, findSpecific)
	if err != nil {
		return nil, err
	}
	return resultsScan, nil
}
