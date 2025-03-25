package main

import (
	"log"
	"os"
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
