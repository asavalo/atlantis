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

	if bytes.IndexByte(input, 'A') == 2 {
		fmt.Println("GOOD")
	} else {
		fmt.Println("BAD")
	}
}
