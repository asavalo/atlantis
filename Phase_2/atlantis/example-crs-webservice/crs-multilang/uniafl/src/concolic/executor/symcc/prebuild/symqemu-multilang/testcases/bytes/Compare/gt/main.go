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
    pass := []byte("GOOD")
    if bytes.Compare(input, pass) > 0 {
        fmt.Println("GOOD")
    } else {
        fmt.Println("BAD")
    }
}
