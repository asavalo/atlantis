package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	pass := "GOOD"

	cmp := strings.Compare(input, pass)

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
