// Package pvss implements Publicly Verifiable Secret Sharing (PVSS)
// using Feldman's VSS scheme with elliptic curve cryptography
package pvss

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// CurveType represents the elliptic curve used
type CurveType string

const (
	// CurveP256 represents the P-256 curve
	CurveP256 CurveType = "p256"
	// Note: secp256k1 support removed until proper implementation available
)

// Point represents a point on an elliptic curve
type Point struct {
	X, Y *big.Int
}

// IsInfinity checks if the point is the point at infinity
func (p *Point) IsInfinity() bool {
	return p.X == nil || p.Y == nil
}

// Equal checks if two points are equal
func (p *Point) Equal(other *Point) bool {
	if p.IsInfinity() && other.IsInfinity() {
		return true
	}
	if p.IsInfinity() || other.IsInfinity() {
		return false
	}
	return p.X.Cmp(other.X) == 0 && p.Y.Cmp(other.Y) == 0
}

// PublicParameters contains the public parameters for PVSS
type PublicParameters struct {
	Curve     elliptic.Curve `json:"-"`
	CurveType CurveType      `json:"curve_type"`
	Generator *Point         `json:"generator"`
	Order     *big.Int       `json:"order"`
}

// PolynomialCommitment represents a commitment to a polynomial
type PolynomialCommitment struct {
	Commitments []*Point `json:"commitments"` // C_i = g^{a_i} for coefficients a_i
}

// PVSSShare represents a PVSS share with its proof
type PVSSShare struct {
	Index      int                   `json:"index"`       // Share index (1-based)
	Value      *big.Int              `json:"value"`       // Share value f(index)
	Commitment *PolynomialCommitment `json:"commitment"`  // Polynomial commitment
	PublicKey  *Point                `json:"public_key"`  // For encryption (future extension)
}

// PVSSSystem represents a PVSS system with specific parameters
type PVSSSystem struct {
	Params    *PublicParameters
	Threshold int // Minimum number of shares needed
	NumShares int // Total number of shares
}

// NewPVSSSystem creates a new PVSS system with the specified parameters
func NewPVSSSystem(curveType CurveType, threshold, numShares int) (*PVSSSystem, error) {
	if threshold <= 0 || threshold > numShares {
		return nil, fmt.Errorf("threshold must be between 1 and %d", numShares)
	}

	params, err := generatePublicParameters(curveType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate public parameters: %w", err)
	}

	return &PVSSSystem{
		Params:    params,
		Threshold: threshold,
		NumShares: numShares,
	}, nil
}

// generatePublicParameters generates public parameters for the specified curve
func generatePublicParameters(curveType CurveType) (*PublicParameters, error) {
	var curve elliptic.Curve
	
	switch curveType {
	case CurveP256:
		curve = elliptic.P256()
	default:
		return nil, fmt.Errorf("unsupported curve type: %s (supported: p256)", curveType)
	}

	// Use the standard generator point
	gx, gy := curve.Params().Gx, curve.Params().Gy
	generator := &Point{X: gx, Y: gy}
	
	order := curve.Params().N

	return &PublicParameters{
		Curve:     curve,
		CurveType: curveType,
		Generator: generator,
		Order:     order,
	}, nil
}

// GenerateShares creates PVSS shares for a given secret
func (pvss *PVSSSystem) GenerateShares(secret []byte) ([]*PVSSShare, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("secret cannot be empty")
	}

	// Process secret to ensure it fits in the field properly
	processedSecret := pvss.processSecret(secret)
	
	// Convert processed secret to big integer
	secretInt := new(big.Int).SetBytes(processedSecret)

	// Generate random polynomial coefficients
	// f(x) = secret + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
	coefficients := make([]*big.Int, pvss.Threshold)
	coefficients[0] = secretInt // f(0) = secret

	for i := 1; i < pvss.Threshold; i++ {
		coeff, err := rand.Int(rand.Reader, pvss.Params.Order)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random coefficient: %w", err)
		}
		coefficients[i] = coeff
	}

	// Create polynomial commitment
	commitment, err := pvss.createPolynomialCommitment(coefficients)
	if err != nil {
		return nil, fmt.Errorf("failed to create polynomial commitment: %w", err)
	}

	// Generate shares
	shares := make([]*PVSSShare, pvss.NumShares)
	for i := 1; i <= pvss.NumShares; i++ {
		shareValue := pvss.evaluatePolynomial(coefficients, big.NewInt(int64(i)))
		
		shares[i-1] = &PVSSShare{
			Index:      i,
			Value:      shareValue,
			Commitment: commitment,
		}
	}

	return shares, nil
}

// createPolynomialCommitment creates commitments for polynomial coefficients
func (pvss *PVSSSystem) createPolynomialCommitment(coefficients []*big.Int) (*PolynomialCommitment, error) {
	commitments := make([]*Point, len(coefficients))
	
	for i, coeff := range coefficients {
		// C_i = g^{a_i}
		cx, cy := pvss.Params.Curve.ScalarMult(
			pvss.Params.Generator.X,
			pvss.Params.Generator.Y,
			coeff.Bytes(),
		)
		commitments[i] = &Point{X: cx, Y: cy}
	}

	return &PolynomialCommitment{
		Commitments: commitments,
	}, nil
}

// evaluatePolynomial evaluates the polynomial at a given point
func (pvss *PVSSSystem) evaluatePolynomial(coefficients []*big.Int, x *big.Int) *big.Int {
	result := big.NewInt(0)
	xPower := big.NewInt(1) // x^0 = 1

	for _, coeff := range coefficients {
		// result += coeff * x^i
		term := new(big.Int).Mul(coeff, xPower)
		term.Mod(term, pvss.Params.Order)
		result.Add(result, term)
		result.Mod(result, pvss.Params.Order)
		
		// Update x^i to x^{i+1}
		xPower.Mul(xPower, x)
		xPower.Mod(xPower, pvss.Params.Order)
	}

	return result
}

// VerifyShare verifies that a PVSS share is valid against its commitment
func (pvss *PVSSSystem) VerifyShare(share *PVSSShare) error {
	if share.Commitment == nil {
		return fmt.Errorf("share missing commitment")
	}

	if len(share.Commitment.Commitments) != pvss.Threshold {
		return fmt.Errorf("commitment has wrong number of elements: expected %d, got %d",
			pvss.Threshold, len(share.Commitment.Commitments))
	}

	// Verify: g^{f(i)} = ∏_{j=0}^{t-1} C_j^{i^j}
	// Left side: g^{share_value}
	leftX, leftY := pvss.Params.Curve.ScalarMult(
		pvss.Params.Generator.X,
		pvss.Params.Generator.Y,
		share.Value.Bytes(),
	)

	// Right side: ∏_{j=0}^{t-1} C_j^{i^j}
	rightX, rightY := big.NewInt(0), big.NewInt(0) // Start with point at infinity
	x := big.NewInt(int64(share.Index))
	xPower := big.NewInt(1) // i^0 = 1

	for j, commitment := range share.Commitment.Commitments {
		// C_j^{i^j}
		termX, termY := pvss.Params.Curve.ScalarMult(
			commitment.X,
			commitment.Y,
			xPower.Bytes(),
		)

		// Add to running product
		if j == 0 {
			rightX, rightY = termX, termY
		} else {
			rightX, rightY = pvss.Params.Curve.Add(rightX, rightY, termX, termY)
		}

		// Update i^j to i^{j+1}
		xPower.Mul(xPower, x)
		xPower.Mod(xPower, pvss.Params.Order)
	}

	// Check if left side equals right side
	if leftX.Cmp(rightX) != 0 || leftY.Cmp(rightY) != 0 {
		return fmt.Errorf("share verification failed: commitment mismatch")
	}

	return nil
}

// RecoverSecret reconstructs the secret from valid shares using Lagrange interpolation
func (pvss *PVSSSystem) RecoverSecret(shares []*PVSSShare) ([]byte, error) {
	if len(shares) < pvss.Threshold {
		return nil, fmt.Errorf("insufficient shares: need %d, got %d", pvss.Threshold, len(shares))
	}

	// Verify all shares first
	for i, share := range shares {
		if err := pvss.VerifyShare(share); err != nil {
			return nil, fmt.Errorf("share %d verification failed: %w", i, err)
		}
	}

	// Use first threshold shares for reconstruction
	shares = shares[:pvss.Threshold]

	// Lagrange interpolation to recover f(0) = secret
	secret := big.NewInt(0)

	for i, share := range shares {
		// Calculate Lagrange coefficient
		numerator := big.NewInt(1)
		denominator := big.NewInt(1)

		xi := big.NewInt(int64(share.Index))

		for j, otherShare := range shares {
			if i == j {
				continue
			}

			xj := big.NewInt(int64(otherShare.Index))

			// numerator *= (0 - x_j) = -x_j
			numerator.Mul(numerator, new(big.Int).Neg(xj))
			numerator.Mod(numerator, pvss.Params.Order)

			// denominator *= (x_i - x_j)
			diff := new(big.Int).Sub(xi, xj)
			denominator.Mul(denominator, diff)
			denominator.Mod(denominator, pvss.Params.Order)
		}

		// coefficient = numerator / denominator (mod order)
		denomInverse := new(big.Int).ModInverse(denominator, pvss.Params.Order)
		if denomInverse == nil {
			return nil, fmt.Errorf("failed to compute modular inverse for Lagrange coefficient")
		}

		coefficient := new(big.Int).Mul(numerator, denomInverse)
		coefficient.Mod(coefficient, pvss.Params.Order)

		// secret += coefficient * share_value
		term := new(big.Int).Mul(coefficient, share.Value)
		term.Mod(term, pvss.Params.Order)
		secret.Add(secret, term)
		secret.Mod(secret, pvss.Params.Order)
	}

	// Convert back to bytes, preserving 32-byte length (PVSS expects fixed-size secrets)
	secretBytes := make([]byte, 32)
	secret.FillBytes(secretBytes)
	
	return secretBytes, nil
}

// processSecret processes the secret to fit within the elliptic curve field
func (pvss *PVSSSystem) processSecret(secret []byte) []byte {
	// For secrets larger than 32 bytes, hash them down
	if len(secret) > 32 {
		hash := sha256.Sum256(secret)
		return hash[:]
	}
	
	// For smaller secrets, pad with zeros if needed
	if len(secret) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(secret):], secret)
		return padded
	}
	
	return secret
}