// package fdp

// import (
// 	// "fmt"
// 	fuzz "github.com/AdaLogics/go-fuzz-headers"
// )

// func FuzzCalc(data []byte) int {

// 	if len(data) > 0x100 {
// 		return 0
// 	}

// 	f := fuzz.NewConsumer(data)

// 	a, err := f.GetUint32()
// 	if err != nil {
// 		return 0 
// 	}
// 	// calc(a)
// 	b, err := f.GetUint32()
// 	if err != nil {
// 		return 0 
// 	}

// 	d, err := f.GetString()
// 	if err != nil {
// 		return 0
// 	}

// 	e, err := f.GetString()
// 	if err != nil {
// 		return 0
// 	}

// 	ds := Demostruct{
// 		a: a,
// 		b: b,
// 		d: d,
// 		e: e,
// 	}
	
// 	calc(&ds)
// 	// fmt.Printf("FuzzTest Result: a: %d, b: %d, c (a + b): %d, d: %s\n", ds.a, ds.b, ds.c, ds.d)
	
// 	return 1
// }

package fdp

import (
	"encoding/binary"
)

func FuzzCalc(data []byte) int {

	if len(data) > 8 {
		return 0
	}

	a := binary.BigEndian.Uint32(data[:4])
	b := binary.BigEndian.Uint32(data[4:8])
	d := string(data[8:])

	ds := Demostruct {
		a: a,
		b: b,
		d: d,
	}
	calc(&ds)
	return 1
}