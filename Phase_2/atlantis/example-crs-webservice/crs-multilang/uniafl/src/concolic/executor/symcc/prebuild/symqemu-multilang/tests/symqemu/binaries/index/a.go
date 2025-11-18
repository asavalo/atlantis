package main

import (
	"fmt"
	"os"
)

func main() {
	numbers := []int{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
    arr := [4]int{1, 2, 3, 4}
    var b [1]byte
    os.Stdin.Read(b[:])

	var input = arr[int(b[0]) - 0x30]
    fmt.Printf("choice %d", input)
	// Read input from stdin instead of a file
	// fmt.Print("Enter index: ")
	// // var index int
	// // fmt.Scanf("%d", &index)
	// reader := bufio.NewReader(os.Stdin)
	// input, err := reader.ReadString('\n')
	// if err != nil {
	//     fmt.Println("Error reading input:", err)
	//     return
	// }

	// // Remove the newline character from the input
	// input = input[:len(input)-1]

	// input = input - 0x30
	// Convert the input to an integer
	// index, err := strconv.Atoi(input)
	// if err != nil {
	//     fmt.Println("Invalid index:", err)
	//     return
	// }

	// Match the index with the number in the array
	if input == 0 {
		fmt.Println("index 0, number:", numbers[input])
		// } else if index == 1 {
		// 	fmt.Println("index 1, number:", numbers[index])
		// } else if index == 2 {
		// 	fmt.Println("index 2, number:", numbers[index])
		// } else if index == 3 {
		// 	fmt.Println("index 3, number:", numbers[index])
		// } else if index == 4 {
		// 	fmt.Println("index 4, number:", numbers[index])
		// } else if index == 5 {
		// 	fmt.Println("index 5, number:", numbers[index])
		// } else if index == 6 {
		// 	fmt.Println("index 6, number:", numbers[index])
	} else {
		fmt.Println("index ?, number:", numbers[input])
	}
}
