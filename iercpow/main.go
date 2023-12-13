package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

var (
	ADDR_ZERO              = common.HexToAddress("0x0000000000000000000000000000000000000000")
	LEN_FOR_THREADS uint64 = 100000
	GlobalCount     atomic.Uint64
	LastCount       uint64 = 0
)

type MatchedTx struct {
	WalletAddr common.Address     `json:"wallet_addr"`
	Tx         *types.Transaction `json:"tx"`
	RawData    string             `json:"raw_tx"`
}

type MintConfig struct {
	RPCNode     string   `json:"rpc"`
	SendTx      bool     `json:"sendTx"`
	Count       int      `json:"count"`
	Threads     int      `json:"threads"`
	P           string   `json:"p"`
	HashPre     string   `json:"hashPre"`
	Tick        string   `json:"tick"`
	Amt         string   `json:"amt"`
	PrivateKeys []string `json:"private_keys"`
}

type Worker struct {
	index        int
	m            MintConfig
	findHashChan chan *types.Transaction
	nonce        uint64
	curNonce     *uint64
	start        uint64
	threads      uint64
	wg           *sync.WaitGroup
	w            *Wallet
}

type MatchCount struct {
	count int
	nonce uint64
}

func newWorker(index int, findHashChan chan *types.Transaction, nonce *uint64, start uint64, threads uint64, mintData *MintConfig, w *Wallet, wg *sync.WaitGroup) *Worker {
	return &Worker{
		index:        index,
		findHashChan: findHashChan,
		nonce:        *nonce,
		curNonce:     nonce,
		start:        start,
		threads:      threads,
		wg:           wg,
		m:            *mintData,
		w:            w,
	}
}

func (w *Worker) startMine() {
	fmt.Println("start mine nonce", w.nonce)
	fixedStr := fmt.Sprintf("data:application/json,{\"p\":\"%s\",\"op\":\"mint\",\"tick\":\"%s\",\"amt\":\"%s\",", w.m.P, w.m.Tick, w.m.Amt)
	value := big.NewInt(0)

	innerTx := &types.DynamicFeeTx{
		ChainID:   w.w.ChainID,
		Nonce:     w.nonce,
		GasTipCap: new(big.Int).Mul(big.NewInt(1000000000), big.NewInt(10)),  // maxPriorityFeePerGas 10
		GasFeeCap: new(big.Int).Mul(big.NewInt(1000000000), big.NewInt(100)), // max Fee 100
		Gas:       30000,
		To:        &ADDR_ZERO,
		Value:     value,
	}

	var t uint64 = 0
	for ; ; t++ {
		start := w.start + w.threads*t*LEN_FOR_THREADS
		end := start + LEN_FOR_THREADS
		for nonce := start; nonce < end; nonce++ {
			GlobalCount.Add(1)
			inputStr := fmt.Sprintf("%s\"nonce\":\"%d\"}", fixedStr, nonce)
			innerTx.Data = []byte(inputStr)
			tx := types.NewTx(innerTx)
			signTx, err := w.w.SignTx(tx)
			if err != nil {
				panic(err)
			}
			if strings.HasPrefix(signTx.Hash().String(), w.m.HashPre) {
				fmt.Println("find matched hash", signTx.Hash().Hex(), "exit", w.index)
				w.findHashChan <- signTx
				w.wg.Done()
				return
			}

			if w.nonce != *w.curNonce {
				fmt.Println("exit find hash", w.index)
				w.wg.Done()
				return
			}
		}
	}
}

func HashRateStatistic() {
	interval := 5 * time.Second
	timer := time.NewTicker(interval)

	go func() {
		for {
			select {
			case <-timer.C:
				count := GlobalCount.Load() - LastCount
				LastCount = GlobalCount.Load()
				fmt.Printf("Hash count %d, Hashrate: %dH/s\n", count, count/5)
			}
		}
	}()
}

func initCfg() *MintConfig {
	var mintData MintConfig
	content, _ := os.ReadFile("config.json")
	err := json.Unmarshal(content, &mintData)
	if err != nil {
		fmt.Println("Read config json error")
		return nil
	}
	return &mintData
}

func initMatchedTx() []*MatchedTx {
	matchedTxs := make([]*MatchedTx, 0)
	content, err := os.ReadFile("matchtx.json")
	if err != nil {
		fmt.Println("Read matchtx json error, ignore")
	} else {
		err = json.Unmarshal(content, &matchedTxs)
		if err != nil {
			fmt.Println("Read config json error")
		}
	}
	return matchedTxs
}

func main() {
	var chainId int64 = 1
	mintConfig := initCfg()
	if mintConfig == nil {
		fmt.Println("get config error, pls set config.json")
		return
	}

	client, err := ethclient.Dial(mintConfig.RPCNode)
	if err != nil {
		fmt.Println("Connect rpc error")
		return
	}
	// 检查已经存好的，避免重跑
	findTxs := make([]MatchedTx, 0)
	matchedCount := make(map[string]*MatchCount, 0)
	matchTxs := initMatchedTx()
	for _, mtx := range matchTxs {
		addr := mtx.WalletAddr.String()
		mc, ok := matchedCount[addr]
		if !ok {
			mc = &MatchCount{
				count: 0,
				nonce: mtx.Tx.Nonce(),
			}
			matchedCount[addr] = mc
		} else {
			mc.count++
			mc.nonce = mtx.Tx.Nonce()
		}

		matchData := MatchedTx{
			WalletAddr: mtx.WalletAddr,
			Tx:         mtx.Tx,
			RawData:    mtx.RawData,
		}
		findTxs = append(findTxs, matchData)

		fmt.Println("Addr", addr, "already find", mc.count, "nonce", mc.nonce)
	}

	wallets := make([]*Wallet, 0)
	for idx, pkey := range mintConfig.PrivateKeys {
		w, err := NewWallet(pkey, client, chainId)
		if err != nil {
			fmt.Println("Create wallet error with index", idx, "pkey", "err", err)
			continue
		}
		wallets = append(wallets, w)
		fmt.Println("Add wallet:", w.Address)
	}

	HashRateStatistic()

	var wg sync.WaitGroup
	for _, w := range wallets {
		wNonce, err := w.GetPendingNonce()
		if err != nil {
			fmt.Println("Wallet", w.Address, "get nonce error")
			continue
		}

		timestamp := time.Now().UnixMilli()
		for i := 0; i < mintConfig.Count; i++ {
			onHashFindChn := make(chan *types.Transaction)
			if mc, ok := matchedCount[w.Address.String()]; ok {
				if mc.count >= i {
					wNonce = mc.nonce + 1
					continue
				}
			}

			wg.Add(mintConfig.Threads)
			for t := 0; t < mintConfig.Threads; t++ {
				start := uint64(timestamp) + uint64(t)*LEN_FOR_THREADS
				worker := newWorker(t, onHashFindChn, &wNonce, start, uint64(mintConfig.Threads), mintConfig, w, &wg)
				go worker.startMine()
			}

			select {
			case tx := <-onHashFindChn:
				wNonce++
				rawTx, _ := w.GetRawTx(tx)
				err := client.SendTransaction(context.Background(), tx)
				if err != nil {
					fmt.Println("Send Transaction failed", err)
				}
				matchData := MatchedTx{
					WalletAddr: w.Address,
					Tx:         tx,
					RawData:    "0x" + common.Bytes2Hex(rawTx),
				}
				findTxs = append(findTxs, matchData)

				outfile, _ := os.Create("matchtx.json")
				jsonData, err := json.MarshalIndent(findTxs, "", "  ")
				if err != nil {
					fmt.Println("Marshal json error", err)
				}
				outfile.Write(jsonData)
				outfile.Close()
				fmt.Println("find tx hash:", tx.Hash().Hex())
			}
			wg.Wait()
		}
	}

}
