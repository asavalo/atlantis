package fdp

import (
	// "fmt"
)

type Demostruct struct {
	a uint32
	b uint32
	c uint32
	d string
}

func calc(d *Demostruct) {
	// Add
	d.c = d.a + d.b
	// fmt.Printf("[calc] a: %d, b: %d, c (a + b): %d, d: %s\n", d.a, d.b, d.c, d.d)
	if d.c == 0xc8c8c8c8 && d.d == "owienflkasndf" {
	// if (d.c == 0xc8c8c8c8) {
		panic("panic triggered!!!")
	}
}
// func calc(a uint32) {
// 	if (a == 0x0c0c0c0c) {
// 		panic("panic triggered")
// 	}
// }
// func check() {
// 	fmt.Printf("asdf\n");
// }

func main() {

	// var a uint32 = 4

	// calc(a)
	d := Demostruct{
		a: 5,
		b: 3,
		d: "Example",
	}

	calc(&d)
}