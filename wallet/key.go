
// Copyright (c) 2013-2022 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.


// Credit goes to btcsuite developers or the btcsuite community
// Also the Decred developers.
// And Also to myself, 😂🤘.



package wallet

// For a better understanding of HD wallets, 
// read here: https://github.com/WebOfTrustInfo/rwot1-sf/blob/master/topics-and-advance-readings/hierarchical-deterministic-keys--bip32-and-beyond.md 

import (
	"crypto/hmac"
	"crypto/sha512"
	"math/big"
	"encoding/binary"


	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcd/btcec"
)

// Key to be used as hmac
var tronKey = []byte("Tron HD-Wallet Seed: ")
var HardenedKeyStart uint32 = 0x80000000 
var maxUint8 uint8 = 1<<8 - 1
// ExtendedKey houses all the information needed to support a hierarchical
// deterministic extended key.  See the package overview documentation for
// more details on how to use extended keys.
type ExtendedKey struct {
	Key       []byte // This will be the pubkey for extended pub keys
	pubKey    []byte // This will only be set for extended priv keys
	chainCode []byte
	depth     uint8
	parentFP  []byte
	childNum  uint32
	version   []byte
	IsPrivate bool
}


// NewExtendedKey returns a new instance of an extended key with the given
// fields.  No error checking is performed here as it's only intended to be a
// convenience method used to create a populated struct. This function should
// only be used by applications that need to create custom ExtendedKeys. All
// other applications should just use NewMaster, Derive, or Neuter.
func NewExtendedKey(version, key, chainCode, parentFP []byte, depth uint8,
	childNum uint32, isPrivate bool) *ExtendedKey {

	// NOTE: The pubKey field is intentionally left nil so it is only
	// computed and memoized as required.
	return &ExtendedKey{
		Key:       key,
		chainCode: chainCode,
		depth:     depth,
		parentFP:  parentFP,
		childNum:  childNum,
		version:   version,
		IsPrivate: isPrivate,
	}
}


// NewParent takes in a seed and creates a parent or a root HD key
// To create a parent private key the generated seed is hashed using HMAC-SHA512.
// SHA512 because hash functions result or return a specific output size, in this case
// The desired output size is 512 bits
// Why 512 bits?
// Why use a HMAC?



// NOTE: There is an extremely small chance (< 1 in 2^127) the provided seed
// will derive to an unusable secret key.  The ErrUnusable error will be
// returned if this should occur, so the caller must check for it and generate a
// new seed accordingly.
// Why ?

// What makes the key unusable?

func NewParent(seed []byte) (key *ExtendedKey, err error) {
		_, err = CheckRecommendedSeed(seed)
		if err  !=  nil  {
				return nil, err
		}
		// compute a message authentication code (mac) using tronKey as the key, 
		// and sha512 as the hash type 
		// What is hmac?
		// Why use hmac?
		mac := hmac.New(sha512.New, tronKey)
		// write data to it, which we would be verifying to prove authenticity
		mac.Write(seed)
		// we compute the hash
		hash := mac.Sum(nil)
		// The hash value is split into two, (1) the left 256 bits (or the first 32 bytes), (2) the right 256 bits 
		// (or the remaining 32 bytes). The left 256 bits \ 32 bytes become the master private key, which is a 
		// normal private key; it’s called the master private key because all other private keys are derived from 
		// this single private key. The right 256 bits \ 32 bytes becomes the chain code.
		bytes32 := len(hash) - 32
		masterPrivateKey := hash[:bytes32]
		chainCode 		 := hash[bytes32:]
		// SetBytes interprets buf as the bytes of a big-endian unsigned integer, 
		// sets z to that value, and returns z.
    	privateKeyNum := new(big.Int).SetBytes(masterPrivateKey)
		// Reference to btcsuite/btcd Go package 
		// The key is checked to be usable using the algorithm below
		// Things to note:
		// btcec.S256 returns a Curve which implements secp256k1.
		// btcec.S256.N 
		// Cmp is a comparison operator method on type big.Int, it compares as follows
		// -1 if privateKeyNum <  btcec.S256().N
		//  0 if privateKeyNum == btcec.S256().N
		// +1 if privateKeyNum >  btcec.S256().N 
		// fmt.Println(privateKeyNum.Cmp( btcec.S256().N))
		// fmt.Println(privateKeyNum.Sign())
		if privateKeyNum.Cmp(btcec.S256().N) >= 0 || privateKeyNum.Sign() == 0 {
			
		}
	
		HDPrivateKeyID:=[4]byte{0x04, 0x88, 0xad, 0xe4}

	
		parentFP := []byte{0x00, 0x00, 0x00, 0x00}

	
		key = NewExtendedKey(HDPrivateKeyID[:],masterPrivateKey, chainCode, parentFP, 0, 0, true)

		return key, nil
}




func DeriveNonStandard(k ExtendedKey, i uint32) (*ExtendedKey, error) {

	// if k.depth == maxUint8 {
	
	// }

	
	isChildHardened := i >= HardenedKeyStart

	if !k.IsPrivate && isChildHardened {
		
	}

	keyLen := 33
	data := make([]byte, keyLen+4)
	if isChildHardened {
		copy(data[1:], k.Key)
	} else {
		copy(data, k.pubKeyBytes())
	}

	binary.BigEndian.PutUint32(data[keyLen:], i)
	hmac512 := hmac.New(sha512.New, k.chainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)

	il := ilr[:len(ilr)/2]
	childChainCode := ilr[len(ilr)/2:]
	ilNum := new(big.Int).SetBytes(il)
	if ilNum.Cmp(btcec.S256().N) >= 0 || ilNum.Sign() == 0 {
	
	}
	var isPrivate bool
	var childKey []byte

	if k.IsPrivate {
		keyNum := new(big.Int).SetBytes(k.Key)
		ilNum.Add(ilNum, keyNum)
		ilNum.Mod(ilNum, btcec.S256().N)
		childKey = ilNum.Bytes()
		isPrivate = true
	} else {
		ilx, ily := btcec.S256().ScalarBaseMult(il)
		if ilx.Sign() == 0 || ily.Sign() == 0 {
		
		}

		pubKey, err := btcec.ParsePubKey(k.Key, btcec.S256())
		if err != nil {
			return nil, err
		}

		childX, childY := btcec.S256().Add(ilx, ily, pubKey.X, pubKey.Y)
		pk := btcec.PublicKey{Curve: btcec.S256(), X: childX, Y: childY}
		childKey = pk.SerializeCompressed()
	}
	
	parentFP := btcutil.Hash160(k.pubKeyBytes())[:4]
	return NewExtendedKey(k.version, childKey, childChainCode, parentFP, k.depth+1, i, isPrivate), nil
}
func (k *ExtendedKey) pubKeyBytes() []byte {
	// Just return the key if it's already an extended public key.
	if !k.IsPrivate {
		return k.Key
	}

	// This is a private extended key, so calculate and memoize the public
	// key if needed.
	if len(k.pubKey) == 0 {
		pkx, pky := btcec.S256().ScalarBaseMult(k.Key)
		pubKey := btcec.PublicKey{Curve: btcec.S256(), X: pkx, Y: pky}
		k.pubKey = pubKey.SerializeCompressed()
	}

	return k.pubKey
}


// func (k *ExtendedKey) DeriveNonStandard(i uint32) (*ExtendedKey, error) {
// 	if k.depth == maxUint8 {
// 		return nil, ErrDeriveBeyondMaxDepth
// 	}

// 	isChildHardened := i >= HardenedKeyStart
// 	if !k.isPrivate && isChildHardened {
// 		return nil, ErrDeriveHardFromPublic
// 	}

// 	keyLen := 33
// 	data := make([]byte, keyLen+4)
// 	if isChildHardened {
// 		copy(data[1:], k.key)
// 	} else {
// 		copy(data, k.pubKeyBytes())
// 	}
// 	binary.BigEndian.PutUint32(data[keyLen:], i)

// 	hmac512 := hmac.New(sha512.New, k.chainCode)
// 	hmac512.Write(data)
// 	ilr := hmac512.Sum(nil)

// 	il := ilr[:len(ilr)/2]
// 	childChainCode := ilr[len(ilr)/2:]

// 	ilNum := new(big.Int).SetBytes(il)
// 	if ilNum.Cmp(btcec.S256().N) >= 0 || ilNum.Sign() == 0 {
// 		return nil, ErrInvalidChild
// 	}

// 	var isPrivate bool
// 	var childKey []byte
// 	if k.isPrivate {
// 		keyNum := new(big.Int).SetBytes(k.key)
// 		ilNum.Add(ilNum, keyNum)
// 		ilNum.Mod(ilNum, btcec.S256().N)
// 		childKey = ilNum.Bytes()
// 		isPrivate = true
// 	} else {
// 		ilx, ily := btcec.S256().ScalarBaseMult(il)
// 		if ilx.Sign() == 0 || ily.Sign() == 0 {
// 			return nil, ErrInvalidChild
// 		}

// 		pubKey, err := btcec.ParsePubKey(k.key, btcec.S256())
// 		if err != nil {
// 			return nil, err
// 		}

// 		childX, childY := btcec.S256().Add(ilx, ily, pubKey.X, pubKey.Y)
// 		pk := btcec.PublicKey{Curve: btcec.S256(), X: childX, Y: childY}
// 		childKey = pk.SerializeCompressed()
// 	}

// 	parentFP := btcutil.Hash160(k.pubKeyBytes())[:4]
// 	return NewExtendedKey(k.version, childKey, childChainCode, parentFP,
// 		k.depth+1, i, isPrivate), nil
// }