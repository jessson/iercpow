package main

import (
	"context"
	"crypto/ecdsa"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type Wallet struct {
	client  *ethclient.Client
	pkey    *ecdsa.PrivateKey
	Address common.Address
	ChainID *big.Int
}

func NewWallet(privateKeyHex string, client *ethclient.Client, chainId int64) (*Wallet, error) {
	wallet := Wallet{
		client:  client,
		ChainID: big.NewInt(chainId),
	}
	var err error
	wallet.pkey, err = crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, err
	}
	wallet.Address = crypto.PubkeyToAddress(wallet.pkey.PublicKey)
	return &wallet, nil
}

func (w *Wallet) GetPendingNonce() (uint64, error) {
	return w.client.NonceAt(context.Background(), w.Address, nil)
}

func (w *Wallet) SignTx(tx *types.Transaction) (*types.Transaction, error) {
	return types.SignTx(tx, types.NewCancunSigner(w.ChainID), w.pkey)
}

func (w *Wallet) SendSignTx(tx *types.Transaction) error {
	return w.client.SendTransaction(context.Background(), tx)
}

func (w *Wallet) GetRawTx(tx *types.Transaction) (hexutil.Bytes, error) {
	data, err := tx.MarshalBinary()
	if err != nil {
		return []byte{}, err
	}
	return data, nil
}
