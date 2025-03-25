package main

import (
	"log"
	"os"
	"path/filepath"
)

/*
It takes the path of a directory as an argument.
If the directory is empty, it returns a true value.
Otherwise, it returns a false value.
*/
func isDirectoryEmpty(path string) bool {
	files, err := os.ReadDir(path)
	if err != nil {
		log.Fatalln(err)
	}
	return len(files) == 0
}

/*
Checks if the directory exists
If it exists, return true.
If it doesn't, return false.
*/
func directoryExists(path string) bool {
	directory, err := os.Stat(path)
	if err != nil {
		return false
	}
	return directory.IsDir()
}

/*
It checks if the file exists
If the file exists, it returns true
If the file does not exist, it returns false
*/
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// Get the file extension of a file
func getFileExtension(path string) string {
	return filepath.Ext(path)
}
