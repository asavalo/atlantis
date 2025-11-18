package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadBytes('\n')
	input = bytes.TrimSpace(input)
	duplicated := bytes.Clone(input)
	pass := []byte("GOOD")
	if bytes.Equal(duplicated, pass) {
		fmt.Println("GOOD")
	} else {
		fmt.Println("BAD")
	}
}
