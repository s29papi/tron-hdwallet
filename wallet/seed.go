package wallet

import (
	"crypto/rand"
	"fmt"
) 


// Seed
// A seed is a randomly generated number which when combined with a chaincode
// derives a new private key. Depending on the level of security you want, the
// larger the bit size of the the randomly generated number you should go for. 
// Difference between a seed and a private key ? A seed is not a private key, no,
// A seed is used to create a private key, and in our case it is used to create a 
// master private key.
// A byte in Go is an unsigned integer of 8 bits. This package would be allowing generation 
// of seeds of 128 bits (16 bytes) - 256 bits (32 bytes) - 512 bits (64 bytes). Choose 
// as prefered. This Package is a learning guide and as such would make reference to 
// were I am learning from, that said, BIP-32() states that the recommended seed size is 
// 256 bits, but it could also range, as I have specified above. 
const (
	SeedMinBytes = 16

	SeedMaxBytes = 64
)

var (
	// ErrInvalidSeedLenBelow describes an error in which the provided seed or
	// seed length is below 128 bits.
	ErrInvalidSeedLenBelow = fmt.Errorf("seed length is below %d bits", SeedMinBytes*8)
	// ErrInvalidSeedLenAbove describes an error in which the provided seed or
	// seed length is Above 512 bits
	ErrInvalidSeedLenAbove = fmt.Errorf("seed length is above %d bits", SeedMaxBytes*8)
)

// 128bit == 16 byte
func New128BitSeed() ([]byte,  error) {
			seed   := make([]byte, 16)
			// reads 16 cryptographically secure pseudorandom numbers from rand.Reader 
			// and writes them to seed.
			_, err := rand.Read(seed)

			return seed, err
}

// 256bit == 32 byte
func New256BitSeed() ([]byte,  error) {
			seed   := make([]byte, 32)
			// reads 32 cryptographically secure pseudorandom numbers from rand.Reader 
			// and writes them to seed.
			_, err := rand.Read(seed)
	
			return seed, err
}

// 512bit == 64 byte
func New512BitSeed() ([]byte,  error) {
			seed   := make([]byte, 64)
			// reads 64 cryptographically secure pseudorandom numbers from rand.Reader 
			// and writes them to seed.
			_, err := rand.Read(seed)
	
			return seed, err
}


// The Recommended seed of this package, is a seed that ranges from 128 bits (16 bytes) - 512 bits (64 bytes)
func recommendedSeed(seed []byte) ([]byte,  error) {
			if SeedMinBytes > len(seed) {
				   return nil, ErrInvalidSeedLenBelow
			}
			if SeedMaxBytes < len(seed) {
				   return nil, ErrInvalidSeedLenAbove
			}

			return seed, nil
} 


// If the seeds bit size is the recommended bit size of the package it returns true with error <nil>
// else it returns false with the particular error
func CheckRecommendedSeed(seed []byte) (bool, error) {
			seed, err := recommendedSeed(seed)
			if err != nil {
				return false, err
			}

			return true, nil
}



