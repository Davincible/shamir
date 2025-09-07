package slip039

// This file implements correct GF(256) field arithmetic for SLIP-0039
// Using the Rijndael polynomial x^8 + x^4 + x^3 + x + 1

// Precomputed tables for GF(256)
var (
	expTable [256]byte
	logTable [256]byte
)

func init() {
	// Generate exp and log tables
	// The generator is 3 in GF(256) with Rijndael polynomial
	x := byte(1)
	generator := byte(3)
	
	for i := 0; i < 255; i++ {
		expTable[i] = x
		logTable[x] = byte(i)
		
		// Multiply by generator
		x = multiplyInternal(x, generator)
	}
	expTable[255] = expTable[0]
	
	// Replace the global tables
	gfExp = expTable
	gfLog = logTable
}

// multiplyInternal performs multiplication using the schoolbook method
// This is used during table generation
func multiplyInternal(a, b byte) byte {
	result := byte(0)
	
	for i := 0; i < 8; i++ {
		if (b>>i)&1 == 1 {
			result ^= a
		}
		
		// Check if high bit is set before shifting
		carry := a & 0x80
		a <<= 1
		if carry != 0 {
			// Reduce by the Rijndael polynomial
			a ^= 0x1B // x^4 + x^3 + x + 1
		}
	}
	
	return result
}