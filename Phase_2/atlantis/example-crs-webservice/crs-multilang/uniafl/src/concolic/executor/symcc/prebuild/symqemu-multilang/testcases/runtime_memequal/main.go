package main

import (
    "fmt"
    "bufio"
    "strings"
    "os"
)

func main() {
    reader := bufio.NewReader(os.Stdin)
    input, _ := reader.ReadString('\n')
    input = strings.TrimSpace(input)
    pass := "GOOD"
    if input == pass {
        fmt.Println("GOOD")
    } else {
        fmt.Println("BAD")
    }
}
