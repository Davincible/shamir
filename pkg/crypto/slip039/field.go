package slip039

// GF(256) field arithmetic using polynomial representation with operations modulo
// the Rijndael irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
// as specified in SLIP-0039 and AES

const (
	// Rijndael polynomial: x^8 + x^4 + x^3 + x + 1
	rijndaelPoly = 0x11B
)

// exp and log tables for efficient multiplication/division in GF(256)
var (
	gfExp [256]byte
	gfLog [256]byte
)

func init() {
	// Initialize exp and log tables for GF(256)
	// Build the exp table using repeated multiplication by 2 (the generator)
	x := byte(1)
	for i := 0; i < 255; i++ {
		gfExp[i] = x
		gfLog[x] = byte(i)
		
		// Multiply by 2 (generator in Rijndael's GF(256))
		x = gfMultiplyBy2(x)
	}
	// Complete the cycle
	gfExp[255] = 1
	// log(0) is undefined, but we set it to 0 for safety
	gfLog[0] = 0
}

// gfMultiply performs multiplication in GF(256) using log/exp tables
func gfMultiply(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	
	// Use log/exp tables for efficient multiplication
	logA := gfLog[a]
	logB := gfLog[b]
	logResult := (int(logA) + int(logB)) % 255
	return gfExp[logResult]
}

// gfMultiplyBy2 multiplies by x (2) in GF(256)
func gfMultiplyBy2(a byte) byte {
	if a&0x80 == 0 {
		return a << 1
	}
	return (a << 1) ^ byte(rijndaelPoly&0xFF)
}

// gfPow raises a to the power of b in GF(256)
func gfPow(a, b byte) byte {
	if b == 0 {
		return 1
	}
	if a == 0 {
		return 0
	}
	
	logA := gfLog[a]
	result := int(logA) * int(b)
	result %= 255
	return gfExp[result]
}

// gfInverse finds the multiplicative inverse of a in GF(256)
func gfInverse(a byte) byte {
	if a == 0 {
		return 0 // technically undefined, but we return 0 for safety
	}
	return gfExp[255-gfLog[a]]
}

// gfDivide performs division in GF(256)
func gfDivide(a, b byte) byte {
	if b == 0 {
		panic("division by zero in GF(256)")
	}
	if a == 0 {
		return 0
	}
	
	logA := int(gfLog[a])
	logB := int(gfLog[b])
	result := (logA - logB + 255) % 255
	return gfExp[result]
}

// gfAdd performs addition in GF(256) (which is XOR)
func gfAdd(a, b byte) byte {
	return a ^ b
}

// gfSubtract performs subtraction in GF(256) (which is also XOR)
func gfSubtract(a, b byte) byte {
	return a ^ b
}

// interpolate performs Lagrange interpolation at point x using the given points
// points is a map of x -> y values
func interpolate(x byte, points map[byte][]byte) []byte {
	if len(points) == 0 {
		return nil
	}
	
	// Get the length of the y values
	var yLen int
	for _, y := range points {
		yLen = len(y)
		break
	}
	
	result := make([]byte, yLen)
	
	// For each byte position in the result
	for k := 0; k < yLen; k++ {
		sum := byte(0)
		
		// Lagrange interpolation formula
		for xi, yi := range points {
			if len(yi) != yLen {
				panic("inconsistent y value lengths")
			}
			
			numerator := byte(1)
			denominator := byte(1)
			
			for xj := range points {
				if xi != xj {
					numerator = gfMultiply(numerator, gfSubtract(x, xj))
					denominator = gfMultiply(denominator, gfSubtract(xi, xj))
				}
			}
			
			if denominator == 0 {
				panic("duplicate x values in interpolation")
			}
			
			term := gfMultiply(yi[k], gfDivide(numerator, denominator))
			sum = gfAdd(sum, term)
		}
		
		result[k] = sum
	}
	
	return result
}