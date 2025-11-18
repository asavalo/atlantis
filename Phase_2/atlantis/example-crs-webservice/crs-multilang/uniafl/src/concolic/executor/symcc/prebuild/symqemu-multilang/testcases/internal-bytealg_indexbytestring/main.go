package main

import (
	"bufio"
	"strings"
	"fmt"
	"os"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if strings.IndexByte(input, 'A') == -1 {
		fmt.Println("GOOD")
	} else {
		fmt.Println("BAD")
	}
}
