package main


import (
	// "errors"
	"crypto/ecdsa"
	
	
	"fmt"
	// "github.com/btcsuite/btcutil/hdkeychain"
	"tron-hdwallet/wallet"
	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/accounts"
	// "github.com/btcsuite/btcutil"
	// "github.com/btcsuite/btcd/chaincfg/chainhash"
	addr "github.com/fbsobreira/gotron-sdk/pkg/address"
)






func main() {
		seed, _ := wallet.New256BitSeed()
		xprvKey, _ := wallet.NewParent(seed)

		// key := xprvKey.Key


		// fmt.Println(xprvKey)
		if !xprvKey.IsPrivate {
			fmt.Println("continue")
		}
		path, _ := accounts.ParseDerivationPath("m/44'/60'/0'/0/0")

		for _, n := range path {
			xprvKey , _ = wallet.DeriveNonStandard(*xprvKey, n)

		}
		fmt.Println(path)
		
		
		privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), xprvKey.Key)

		ptecdsa := privKey.ToECDSA()

		fmt.Println(ptecdsa.D)

		pubkey := ptecdsa.Public()
		fmt.Println(pubkey.(*ecdsa.PublicKey)) // i dont know what this is but it made no difference
		fmt.Println(pubkey)

		a := addr.PubkeyToAddress(*pubkey.(*ecdsa.PublicKey))

		fmt.Println("Master wallet: ", a)

		path, _ = accounts.ParseDerivationPath("m/44'/60'/0'/0/1")

		for _, n := range path {
			xprvKey , _ = wallet.DeriveNonStandard(*xprvKey, n)

		}
		fmt.Println(path)
		
		
		privKey, _ = btcec.PrivKeyFromBytes(btcec.S256(), xprvKey.Key)

		ptecdsa = privKey.ToECDSA()

		fmt.Println(ptecdsa.D)

		pubkey = ptecdsa.Public()
		fmt.Println(pubkey.(*ecdsa.PublicKey)) // i dont know what this is but it made no difference
		fmt.Println(pubkey)

		a = addr.PubkeyToAddress(*pubkey.(*ecdsa.PublicKey))

		fmt.Println("User wallet: ", a)

		
		
		// return privKey, nil
	
}












































// func CreateAddressBySeed(seed []byte) (string, error) {
// 	if len(seed) != 75 {
// 		return "", fmt.Errorf("seed len=[%d] is not equal 32", len(seed))
// 	}
// 	priv, _ := btcec.PrivKeyFromBytes(seed)
// 	fmt.Printf("%+v",*priv)
// 	if priv == nil {
// 		return "", errors.New("priv is nil ptr")
// 	}
// 	a := addr.PubkeyToAddress(priv.ToECDSA().PublicKey)
// 	return a.String(), nil
// }