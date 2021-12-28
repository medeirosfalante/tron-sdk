package tronsdk

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/medeirosfalante/tron-sdk/address"
	"github.com/medeirosfalante/tron-sdk/common"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
)

type TronAccount struct {
	Mnemonic string
	Path     string
	privKey  *ecdsa.PrivateKey
	pubKey   string
}

type TRC20 struct {
	TokenID         string  `json:"tokenId"`
	Balance         string  `json:"balance"`
	TokenName       string  `json:"tokenName"`
	TokenAbbr       string  `json:"tokenAbbr"`
	TokenDecimal    int     `json:"tokenDecimal"`
	TokenType       string  `json:"tokenType"`
	TokenPriceInTrx float64 `json:"tokenPriceInTrx"`
}

type Balance struct {
	TokenPriceInTrx float64 `json:"tokenPriceInTrx"`
	TokenID         string  `json:"tokenId"`
	Balance         string  `json:"balance"`
	TokenName       string  `json:"tokenName"`
	TokenDecimal    int     `json:"tokenDecimal"`
	TokenAbbr       string  `json:"tokenAbbr"`
	TokenType       string  `json:"tokenType"`
}

type Account struct {
	TRC20    []TRC20   `json:"trc20token_balances"`
	TRC10    []Balance `json:"tokenBalances"`
	Balances []Balance `json:"balances"`
}

func NewTronAccount(mnemonic string, path string) (TronAccount, error) {

	key, err := PrivateKeyPath(mnemonic, path)
	if err != nil {
		return TronAccount{}, err
	}

	pkey, err := PublicKeyPath(mnemonic, path)

	if err != nil {
		return TronAccount{}, err
	}

	return TronAccount{
		Mnemonic: mnemonic,
		Path:     path,
		privKey:  key,
		pubKey:   pkey,
	}, nil
}

func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, 4096)
	return privkey, &privkey.PublicKey
}

func (a TronAccount) PubKeyFromPath(path string) (string, error) {

	wallet, err := hdwallet.NewFromMnemonic(a.Mnemonic)
	if err != nil {
		return "", fmt.Errorf("mnemonic %s", err.Error())
	}

	p := hdwallet.MustParseDerivationPath(path)
	account, err := wallet.Derive(p, false)
	if err != nil {
		return "", fmt.Errorf("account %s", err.Error())
	}

	publicKeyECDSA, err := wallet.PublicKey(account)
	if err != nil {
		return "", fmt.Errorf("pkey %s", err.Error())
	}

	addr := address.PubkeyToAddress(*publicKeyECDSA)

	return addr.String(), nil

}

func (a TronAccount) PublicKey() string {
	return a.pubKey
}

func (a TronAccount) PrivateKey() *ecdsa.PrivateKey {
	return a.privKey
}

func PrivateKeyPath(mnemonic, path string) (*ecdsa.PrivateKey, error) {
	wallet, err := hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}

	p := hdwallet.MustParseDerivationPath(path)
	account, err := wallet.Derive(p, false)
	if err != nil {
		return nil, err
	}

	privateKeyECDSA, err := wallet.PrivateKey(account)
	if err != nil {
		return nil, err
	}

	return privateKeyECDSA, nil
}

func PublicKeyPath(mnemonic, path string) (string, error) {

	wallet, err := hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		return "", fmt.Errorf("mnemonic %s", err.Error())
	}

	p := hdwallet.MustParseDerivationPath(path)
	account, err := wallet.Derive(p, false)
	if err != nil {
		return "", fmt.Errorf("account %s", err.Error())
	}

	publicKeyECDSA, err := wallet.PublicKey(account)
	if err != nil {
		return "", fmt.Errorf("pkey %s", err.Error())
	}

	addr := address.PubkeyToAddress(*publicKeyECDSA)

	log.Println(addr.String())

	return addr.String(), nil
}

const (
	// HashLength is the expected length of the hash
	HashLength = 32
	// AddressLength is the expected length of the address
	AddressLength = 21
	// AddressLengthBase58 is the expected length of the address in base58format
	AddressLengthBase58 = 34
	// TronBytePrefix is the hex prefix to address
	TronBytePrefix = byte(0x41)
)

// Address represents the 21 byte address of an Tron account.
type Address []byte

// Bytes get bytes from address
func (a Address) Bytes() []byte {
	return a[:]
}

// Hex get bytes from address in string
func (a Address) Hex() string {
	return common.ToHex(a[:])
}

// BigToAddress returns Address with byte values of b.
// If b is larger than len(h), b will be cropped from the left.
func BigToAddress(b *big.Int) Address {
	id := b.Bytes()
	base := bytes.Repeat([]byte{0}, AddressLength-len(id))
	return append(base, id...)
}

// HexToAddress returns Address with byte values of s.
// If s is larger than len(h), s will be cropped from the left.
func HexToAddress(s string) Address {
	addr, err := common.FromHex(s)
	if err != nil {
		return nil
	}
	return addr
}

// Base58ToAddress returns Address with byte values of s.
func Base58ToAddress(s string) (Address, error) {
	addr, err := common.DecodeCheck(s)
	if err != nil {
		return nil, err
	}
	return addr, nil
}

// Base64ToAddress returns Address with byte values of s.
func Base64ToAddress(s string) (Address, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return Address(decoded), nil
}

// String implements fmt.Stringer.
func (a Address) String() string {
	if a[0] == 0 {
		return new(big.Int).SetBytes(a.Bytes()).String()
	}
	return common.EncodeCheck(a.Bytes())
}

// PubkeyToAddress returns address from ecdsa public key
func PubkeyToAddress(p ecdsa.PublicKey) Address {
	address := crypto.PubkeyToAddress(p)

	addressTron := make([]byte, 0)
	addressTron = append(addressTron, TronBytePrefix)
	addressTron = append(addressTron, address.Bytes()...)
	return addressTron
}
