package slip039

import "fmt"

// RS1024 checksum implementation for SLIP-0039
// Reed-Solomon code over GF(1024) for error detection

const (
	// Checksum length in words
	checksumWords = 3
)

// Generator polynomial coefficients for RS1024
var generatorPoly = [10]uint32{
	0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009,
	0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120,
}

// rs1024Polymod computes the Reed-Solomon polymod for the given values
func rs1024Polymod(values []int) uint32 {
	chk := uint32(1)
	
	for _, v := range values {
		b := chk >> 20
		chk = (chk & 0xfffff) << 10 ^ uint32(v)
		
		for i := 0; i < 10; i++ {
			if (b>>i)&1 == 1 {
				chk ^= generatorPoly[i]
			}
		}
	}
	
	return chk
}

// rs1024CreateChecksum creates a checksum for the given customization string and data
func rs1024CreateChecksum(customizationString string, data []int) []int {
	// Convert customization string to values
	values := make([]int, 0, len(customizationString)+len(data)+3)
	for _, c := range customizationString {
		values = append(values, int(c))
	}
	values = append(values, data...)
	
	// Add padding for checksum calculation
	values = append(values, 0, 0, 0)
	
	// Calculate polymod and extract checksum
	polymod := rs1024Polymod(values) ^ 1
	
	checksum := make([]int, 3)
	for i := 0; i < 3; i++ {
		checksum[i] = int((polymod >> (10 * (2 - i))) & 1023)
	}
	
	return checksum
}

// rs1024VerifyChecksum verifies the checksum for the given customization string and data
func rs1024VerifyChecksum(customizationString string, data []int) bool {
	// Convert customization string to values
	values := make([]int, 0, len(customizationString)+len(data))
	for _, c := range customizationString {
		values = append(values, int(c))
	}
	values = append(values, data...)
	
	// Verify checksum
	return rs1024Polymod(values) == 1
}

// addChecksum adds a checksum to the share data
func addChecksum(shareData []int, extendable bool) []int {
	customizationString := "shamir"
	if extendable {
		customizationString = "shamir_extendable"
	}
	
	checksum := rs1024CreateChecksum(customizationString, shareData)
	result := make([]int, len(shareData)+len(checksum))
	copy(result, shareData)
	copy(result[len(shareData):], checksum)
	
	return result
}

// verifyChecksum verifies and removes the checksum from share data
func verifyChecksum(shareDataWithChecksum []int, extendable bool) ([]int, error) {
	if len(shareDataWithChecksum) < checksumWords {
		return nil, fmt.Errorf("share data too short for checksum")
	}
	
	customizationString := "shamir"
	if extendable {
		customizationString = "shamir_extendable"
	}
	
	if !rs1024VerifyChecksum(customizationString, shareDataWithChecksum) {
		return nil, fmt.Errorf("invalid checksum")
	}
	
	// Return data without checksum
	return shareDataWithChecksum[:len(shareDataWithChecksum)-checksumWords], nil
}