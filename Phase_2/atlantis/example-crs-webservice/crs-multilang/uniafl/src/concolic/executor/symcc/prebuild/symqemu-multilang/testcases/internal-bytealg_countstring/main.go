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
	cnt := strings.Count(input, "G")
	if cnt == 5 {
		fmt.Println("GOOD")
	} else {
		fmt.Println("BAD")
	}
}
