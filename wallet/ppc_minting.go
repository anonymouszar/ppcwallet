// Copyright (c) 2014-2014 PPCD developers.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"fmt"
	"sync"
	"time"

	"github.com/kac-/umint"
	"github.com/ppcsuite/btcutil"
	"github.com/ppcsuite/ppcd/txscript"
	"github.com/ppcsuite/ppcd/wire"
	"github.com/ppcsuite/ppcutil"
	"github.com/ppcsuite/ppcwallet/txstore"
	"github.com/ppcsuite/ppcwallet/waddrmgr"
)

type Minter struct {
	sync.Mutex
	wallet  *Wallet
	started bool
	wg      sync.WaitGroup
	quit    chan struct{}
}

// Start begins the minting process.  Calling this function when the minter has
// already been started will have no effect.
//
// This function is safe for concurrent access.
func (m *Minter) Start() {
	m.Lock()
	defer m.Unlock()

	// Nothing to do if the miner is already running.
	if m.started {
		return
	}

	m.quit = make(chan struct{})
	m.wg.Add(1)

	go m.mintBlocks()

	m.started = true
	log.Infof("Minter started")
}

// Stop gracefully stops the mining process by signalling all workers, and the
// speed monitor to quit.  Calling this function when the CPU miner has not
// already been started will have no effect.
//
// This function is safe for concurrent access.
func (m *Minter) Stop() {
	m.Lock()
	defer m.Unlock()

	// Nothing to do if the miner is not currently running.
	if !m.started {
		return
	}

	close(m.quit)
	m.wg.Wait()
	m.started = false
	log.Infof("Minter stopped")
}

// WaitForShutdown blocks until all minter goroutines have finished executing.
func (m *Minter) WaitForShutdown() {
	m.wg.Wait()
}

// mintBlocks is a worker that is controlled by the miningWorkerController.
// It is self contained in that it creates block templates and attempts to solve
// them while detecting when it is performing stale work and reacting
// accordingly by generating a new block template.  When a block is solved, it
// is submitted.
//
// It must be run as a goroutine.
func (m *Minter) mintBlocks() {

	defer m.wg.Done()

	log.Tracef("Starting minting blocks worker")

out:
	for {
		// Quit when the miner is stopped.
		select {
		case <-m.quit:
			break out
		default:
			// Non-blocking select to fall through
		}

		// No point in searching for a solution before the chain is
		// synced.  Also, grab the same lock as used for block
		// submission, since the current block will be changing and
		// this would otherwise end up building a new block template on
		// a block that is in the process of becoming stale.
		if !m.wallet.ChainSynced() {
			time.Sleep(time.Second)
			continue
		}

		searchTime := time.Now().Unix()
		m.wallet.CreateCoinStake(searchTime)

		time.Sleep(time.Millisecond * 500)
	}

	log.Tracef("Minting blocks worker done")
}

// newMinter returns a new instance of a PPC minter for the provided wallet.
// Use Start to begin the minting process.  See the documentation for Minter
// type for more details.
func newMinter(w *Wallet) *Minter {
	return &Minter{
		wallet: w,
	}
}

func (w *Wallet) CreateCoinStake(fromTime int64) (err error) {

	// Get current block's height and hash.
	bs, err := w.chainSvr.BlockStamp()
	if err != nil {
		return
	}

	bits, err := w.chainSvr.CurrentTarget()
	if err != nil {
		return
	}

	params, err := w.chainSvr.Params()
	if err != nil {
		return
	}

	eligibles, err := w.ppcFindEligibleOutputs(6, bs)

	if err != nil || len(eligibles) == 0 {
		return
	}

	txNew := wire.NewMsgTx()

	nBalance, err := w.CalculateBalance(6)

	nCredit := btcutil.Amount(0)
	fKernelFound := false

	nStakeMinAge := params.StakeMinAge
	nMaxStakeSearchInterval := int64(60)
	StakeMinAmount, _ := btcutil.NewAmount(1.0)

	for _, eligible := range eligibles {
		if w.ShuttingDown() {
			return
		}
		var block *txstore.Block
		block, err = eligible.Block()
		if err != nil {
			return
		}
		if eligible.Amount() < StakeMinAmount {
			continue // only count coins meeting min amount requirement
		}
		if block.Time.Unix()+nStakeMinAge > txNew.Time.Unix()-nMaxStakeSearchInterval {
			continue // only count coins meeting min age requirement
		}
		// Verify that block.KernelStakeModifier is defined
		if block.KernelStakeModifier == btcutil.KernelStakeModifierUnknown {
			var ksm uint64
			ksm, err = w.chainSvr.GetKernelStakeModifier(&block.Hash)
			if err != nil {
				log.Errorf("Error getting kernel stake modifier for block %v", &block.Hash)
				return
			} else {
				log.Infof("Found kernel stake modifier for block %v: %v", &block.Hash, ksm)
				block.KernelStakeModifier = ksm
				w.TxStore.MarkDirty()
			}
		}
		tx := eligible.Tx()
		for n := int64(0); n < 60 && !fKernelFound; n++ {
			if w.ShuttingDown() {
				return
			}
			stpl := umint.StakeKernelTemplate{
				//BlockFromTime:  int64(utx.BlockTime),
				BlockFromTime: block.Time.Unix(),
				//StakeModifier:  utx.StakeModifier,
				StakeModifier: block.KernelStakeModifier,
				//PrevTxOffset:   utx.OffsetInBlock,
				PrevTxOffset: tx.Offset(),
				//PrevTxTime:     int64(utx.Time),
				PrevTxTime: tx.MsgTx().Time.Unix(),
				//PrevTxOutIndex: outPoint.Index,
				PrevTxOutIndex: eligible.OutputIndex,
				//PrevTxOutValue: int64(utx.Value),
				PrevTxOutValue: int64(eligible.Amount()),
				IsProtocolV03:  true,
				StakeMinAge:    nStakeMinAge,
				Bits:           bits,
				TxTime:         fromTime - n,
			}
			var success bool
			_, success, err, _ = umint.CheckStakeKernelHash(&stpl)
			if err != nil {
				log.Errorf("Check kernel hash error: %v", err)
				return
			}
			if success {
				log.Infof("Valid kernel hash found!")
				// TODO create coinstake tx
				nCredit += eligible.Amount()
				fKernelFound = true
				break
			}
		}
		if fKernelFound {
			break
		}
	}

	//log.Infof("Credit available: %v / %v", nCredit, nBalance)

	if nCredit <= 0 || nCredit > nBalance {
		return
	}

	// TODO to be continued...

	return
}

// TODO: ppc: default findEligibleOutputs filters by account
func (w *Wallet) ppcFindEligibleOutputs(minconf int, bs *waddrmgr.BlockStamp) ([]txstore.Credit, error) {
	unspent, err := w.TxStore.UnspentOutputs()
	if err != nil {
		return nil, err
	}
	// Filter out unspendable outputs, that is, remove those that (at this
	// time) are not P2PKH outputs.  Other inputs must be manually included
	// in transactions and sent (for example, using createrawtransaction,
	// signrawtransaction, and sendrawtransaction).
	eligible := make([]txstore.Credit, 0, len(unspent))
	for i := range unspent {
		switch txscript.GetScriptClass(unspent[i].TxOut().PkScript) {
		case txscript.PubKeyHashTy:
			if !unspent[i].Confirmed(minconf, bs.Height) {
				continue
			}
			// Coinbase transactions must have have reached maturity
			// before their outputs may be spent.
			if unspent[i].IsCoinbase() {
				target := int(w.chainParams.CoinbaseMaturity)
				if !unspent[i].Confirmed(target, bs.Height) {
					continue
				}
			}

			// Locked unspent outputs are skipped.
			if w.LockedOutpoint(*unspent[i].OutPoint()) {
				continue
			}

			eligible = append(eligible, unspent[i])
		}
	}
	return eligible, nil
}

type FoundStake struct {
	Difficulty float64
	Time       int64
}

func (w *Wallet) FindStake(maxTime int64, diff float64) (foundStakes []FoundStake, err error) {

	// Get ChainParams
	params, err := w.chainSvr.Params()
	if err != nil {
		return
	}

	// Get current block's height and hash.
	bs, err := w.chainSvr.BlockStamp()
	if err != nil {
		return
	}

	bits, err := w.chainSvr.CurrentTarget()
	if err != nil {
		return
	}

	if diff != 0 {
		bits = umint.BigToCompact(ppcutil.DifficultyToTarget(diff))
	}

	log.Infof("Required difficulty: %v (%v)", ppcutil.TargetToDifficulty(bits), bits)

	eligibles, err := w.ppcFindEligibleOutputs(6, bs)

	if err != nil || len(eligibles) == 0 {
		return
	}

	fromTime := time.Now().Unix()
	if maxTime == 0 {
		maxTime = fromTime + 30*24*60*60 // 30 days
	}

	foundStakes = make([]FoundStake, 0)

	nStakeMinAge := params.StakeMinAge
	nMaxStakeSearchInterval := int64(60)
	StakeMinAmount, _ := btcutil.NewAmount(1.0)

	for _, eligible := range eligibles {
		if w.ShuttingDown() {
			return
		}
		var block *txstore.Block
		block, err = eligible.Block()
		if err != nil {
			return
		}
		if eligible.Amount() < StakeMinAmount {
			continue // only count coins meeting min amount requirement
		}
		if block.Time.Unix()+nStakeMinAge > fromTime-nMaxStakeSearchInterval {
			continue // only count coins meeting min age requirement
		}
		// Verify that block.KernelStakeModifier is defined
		if block.KernelStakeModifier == btcutil.KernelStakeModifierUnknown {
			var ksm uint64
			ksm, err = w.chainSvr.GetKernelStakeModifier(&block.Hash)
			if err != nil {
				log.Errorf("Error getting kernel stake modifier for block %v", &block.Hash)
				return
			} else {
				log.Infof("Found kernel stake modifier for block %v: %v", &block.Hash, ksm)
				block.KernelStakeModifier = ksm
				w.TxStore.MarkDirty()
			}
		}

		scriptClass, addresses, _, _ := eligible.Addresses(params)
		log.Infof("Addresses: %v (%v)", addresses, scriptClass)

		tx := eligible.Tx()

		log.Infof("CHECK %v PPCs from %v https://bkchain.org/ppc/tx/%v#o%v",
			float64(eligible.Amount())/1000000.0,
			time.Unix(int64(tx.MsgTx().Time.Unix()), 0).Format("2006-01-02"),
			eligible.OutPoint().Hash, eligible.OutPoint().Index)

		stpl := umint.StakeKernelTemplate{
			//BlockFromTime:  int64(utx.BlockTime),
			BlockFromTime: block.Time.Unix(),
			//StakeModifier:  utx.StakeModifier,
			StakeModifier: block.KernelStakeModifier,
			//PrevTxOffset:   utx.OffsetInBlock,
			PrevTxOffset: tx.Offset(),
			//PrevTxTime:     int64(utx.Time),
			PrevTxTime: tx.MsgTx().Time.Unix(),
			//PrevTxOutIndex: outPoint.Index,
			PrevTxOutIndex: eligible.OutputIndex,
			//PrevTxOutValue: int64(utx.Value),
			PrevTxOutValue: int64(eligible.Amount()),
			IsProtocolV03:  true,
			StakeMinAge:    nStakeMinAge,
			Bits:           bits,
			TxTime:         fromTime,
		}

		for true {
			if w.ShuttingDown() {
				return
			}
			_, succ, ferr, minTarget := umint.CheckStakeKernelHash(&stpl)
			if ferr != nil {
				err = fmt.Errorf("check kernel hash error :%v", ferr)
				return
			}
			if succ {
				comp := umint.IncCompact(umint.BigToCompact(minTarget))
				maximumDiff := ppcutil.TargetToDifficulty(comp)
				log.Infof("MINT %v %v", time.Unix(stpl.TxTime, 0), maximumDiff)
				foundStakes = append(foundStakes, FoundStake{maximumDiff, stpl.TxTime})
			}
			stpl.TxTime++
			if stpl.TxTime > maxTime {
				break
			}
		}
	}

	return
}
