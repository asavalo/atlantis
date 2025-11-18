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
	cnt := bytes.Count(input, []byte("G"))
	if cnt == 5 {
		fmt.Println("GOOD")
	} else {
		fmt.Println("BAD")
	}
}
