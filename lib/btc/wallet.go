package btc

import (
	"bytes"
	"errors"
	"math/big"
	"github.com/lentus/wotscoin/lib/secp256k1"
	"github.com/lentus/wotscoin/lib/xnyss"
	"encoding/hex"
)


// Get ECDSA public key in bitcoin protocol format, from the give private key
func PublicFromPrivate(priv_key []byte, compressed bool) (res []byte) {
	if compressed {
		res = make([]byte, 33)
	} else {
		res = make([]byte, 65)
	}

	if !secp256k1.BaseMultiply(priv_key, res) {
		res = nil
	}
	return
}


// Verify the key pair. Returns nil if everything looks OK
func VerifyKeyPair(priv []byte, publ []byte) error {
	pubSeed := make([]byte, 32)
	ShaHash(priv, pubSeed)

	tree := xnyss.New(priv, pubSeed, false)
	pubKey := tree.PublicKey()
	if !bytes.Equal(publ, pubKey) {
		return errors.New("key verification failed")
	}
	return nil
}

// B_private_key = ( A_private_key + secret ) % N
// Used for implementing Type-2 determinitic keys
func DeriveNextPrivate(p, s []byte) (toreturn []byte) {
	var prv, secret big.Int
	prv.SetBytes(p)
	secret.SetBytes(s)
	res := new(big.Int).Mod(new(big.Int).Add(&prv, &secret), &secp256k1.TheCurve.Order.Int).Bytes()
	toreturn = make([]byte, 32)
	copy(toreturn[32-len(res):], res)
	return
}


// B_public_key = G * secret + A_public_key
// Used for implementing Type-2 determinitic keys
func DeriveNextPublic(public, secret []byte) (out []byte) {
	out = make([]byte, len(public))
	secp256k1.BaseMultiplyAdd(public, secret, out)
	return
}


// returns one TxOut record
func NewSpendOutputs(addr *BtcAddr, amount uint64, testnet bool) ([]*TxOut, error) {
	out := new(TxOut)
	out.Value = amount
	out.Pk_script = addr.OutScript()
	return []*TxOut{out}, nil
}


// Base58 encoded private address with checksum and it's corresponding public key/address
type PrivateAddr struct {
	Version byte
	Key []byte
	*BtcAddr

	PubSeed []byte
	TreeState *xnyss.NYTree
	StateFn string
}


func NewPrivateAddr(key []byte, ver byte, longterm bool) (ad *PrivateAddr) {
	ad = new(PrivateAddr)
	ad.Version = ver
	ad.Key = key
	ad.PubSeed = make([]byte, 32)
	ShaHash(key, ad.PubSeed)
	ad.TreeState = xnyss.New(ad.Key, ad.PubSeed, !longterm)
	pub := ad.TreeState.PublicKey()
	ad.BtcAddr = NewAddrFromPubkey(pub, ver-0x80)
	ad.StateFn = hex.EncodeToString(ad.Hash160[:])
	return
}


func DecodePrivateAddr(s string) (*PrivateAddr, error) {
	pkb := Decodeb58(s)

	if pkb == nil {
		return nil, errors.New("Decodeb58 failed")
	}

	if len(pkb) < 37 {
		return nil, errors.New("Decoded data too short")
	}

	if len(pkb)>38 {
		return nil, errors.New("Decoded data too long")
	}

	var sh [32]byte
	ShaHash(pkb[:len(pkb)-4], sh[:])
	if !bytes.Equal(sh[:4], pkb[len(pkb)-4:]) {
		return nil, errors.New("Checksum error")
	}

	return NewPrivateAddr(pkb[1:33], pkb[0], len(pkb)==38 && pkb[33]==1), nil
}


// Returns base58 encoded private key (with checksum)
func (ad *PrivateAddr) String() string {
	var ha [32]byte
	buf := new(bytes.Buffer)
	buf.WriteByte(ad.Version)
	buf.Write(ad.Key)
	if ad.BtcAddr.IsCompressed() {
		buf.WriteByte(1)
	}
	ShaHash(buf.Bytes(), ha[:])
	buf.Write(ha[:4])
	return Encodeb58(buf.Bytes())
}
