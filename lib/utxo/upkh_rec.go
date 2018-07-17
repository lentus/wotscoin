package utxo

import (
	"bytes"
	"encoding/binary"
)

// A Record represents an unused public key hash in the context of long-term
// addresses based on XNYSS. Every signature created for a long-term address
// advertises one or more public keys to be used in the future, thus forming a
// (forked) chain of public keys and signatures.
//
// A UPKH Record includes the advertised public key hash, the corresponding
// long-term public key hash (which is used to create a long-term address), and
// the block height of the transaction that contains the signed input where the
// UPKH was advertised.
type UpkhRec struct {
	PubKeyHash   [32]byte
	LongTermHash [20]byte

	// The following variables indicate the transaction input where the public
	// key hash was signed. Only the block height is required for functionality,
	// the txid and input nr are recorded for debugging purposes.
	Blockheight uint32
	//TxID        [32]byte
	//Input       uint32
}

func ReadUpkhRec(data []byte) *UpkhRec {
	var key UtxoKeyType
	copy(key[:], data[:UtxoIdxLen])
	return LoadUpkhRec(key, data[UtxoIdxLen:])
}

func LoadUpkhRec(key UtxoKeyType, data []byte) *UpkhRec {
	r := new(UpkhRec)

	copy(r.PubKeyHash[:UtxoIdxLen], key[:])
	offset := len(r.PubKeyHash)-UtxoIdxLen
	copy(r.PubKeyHash[UtxoIdxLen:], data[:offset])

	copy(r.LongTermHash[:], data[offset:])
	offset += len(r.LongTermHash)

	r.Blockheight = binary.LittleEndian.Uint32(data[offset:])
	/*
	offset += 4
	copy(r.TxID[:], data[offset:])
	offset += len(r.TxID)
	r.Input = binary.LittleEndian.Uint32(data[offset:])
	*/
	return r
}

func (r *UpkhRec) Bytes() []byte {
	return append(r.PubKeyHash[:UtxoIdxLen], r.MapBytes()...)
}

func (r *UpkhRec) MapBytes() []byte {
	buf := new(bytes.Buffer)
	buf.Write(r.PubKeyHash[UtxoIdxLen:])
	buf.Write(r.LongTermHash[:])

	temp := make([]byte, 4)
	binary.LittleEndian.PutUint32(temp, r.Blockheight)
	buf.Write(temp)
	/*
	buf.Write(r.TxID[:])
	binary.LittleEndian.PutUint32(temp, r.Input)
	buf.Write(temp)
	*/
	return buf.Bytes()
}

