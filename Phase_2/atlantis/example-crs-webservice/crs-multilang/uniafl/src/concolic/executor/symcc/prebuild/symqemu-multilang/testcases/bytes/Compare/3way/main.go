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
    ret := bytes.Compare(input, pass)
    switch (ret) {
    case -1:
        fmt.Println("lt")
    case 0:
        fmt.Println("eq")
    case 1:
        fmt.Println("gt")
    }
}
