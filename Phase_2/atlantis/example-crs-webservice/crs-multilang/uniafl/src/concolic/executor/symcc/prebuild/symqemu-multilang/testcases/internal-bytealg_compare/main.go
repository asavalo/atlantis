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
	pass := []byte("GOOD")
	cmp := bytes.Compare(input, pass)

	if cmp == 0 {
		fmt.Println("EQ")
	} else {
		fmt.Println("NEQ")
	}

	if cmp < 0 {
		fmt.Println("LT")
	} else {
		fmt.Println("GE")
	}

	if cmp > 0 {
		fmt.Println("GT")
	} else {
		fmt.Println("LE")
	}
}
