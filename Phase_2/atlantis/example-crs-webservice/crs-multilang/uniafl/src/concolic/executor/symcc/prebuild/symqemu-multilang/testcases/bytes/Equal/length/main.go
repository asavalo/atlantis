package main

import (
    "fmt"
    "bytes"
    "bufio"
	"os"
)

func main() {
    reader := bufio.NewReader(os.Stdin)
    input, _ := reader.ReadBytes('\n')
    input = bytes.TrimSpace(input)
    n := int(input[0]) - 0x30;
    x := make([]byte, n)
    for i := 0; i < n; i++ {
        x[i] = 'A';
    }
    if bytes.Equal(input[1:], x) {
        fmt.Println("GOOD")
    } else {
        fmt.Println("BAD")
    }
}
