package main

import ()

func main() {
	// The varaible to the new file name
	var newFileName string = generateRandomString(8)+".txt"
	// Write a file to the current directory
	writeToFile(newFileName, []byte(generateRandomString(1000)))
	// Check if the file exists
	if fileExists(newFileName) {
		// Read the file and return the content as a byte slice
		fileContent := readFileAndReturnAsByte(newFileName)
		// Encrypt the content and save it to an output file
		encryptContent(fileContent, getFilename(newFileName+".PAY"))
		// Securely delete the original file
		secureDelete(newFileName)
	}
}
