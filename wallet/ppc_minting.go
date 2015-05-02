// Copyright (c) 2014-2014 PPCD developers.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/kac-/umint"
	"github.com/ppcsuite/btcutil"
	"github.com/ppcsuite/ppcd/blockchain"
	"github.com/ppcsuite/ppcd/btcec"
	"github.com/ppcsuite/ppcd/chaincfg"
	"github.com/ppcsuite/ppcd/txscript"
	"github.com/ppcsuite/ppcd/wire"
	"github.com/ppcsuite/ppcutil"
	"github.com/ppcsuite/ppcwallet/waddrmgr"
	"github.com/ppcsuite/ppcwallet/wtxmgr"
)

const (
	nStakeSplitAge          = 60 * 60 * 24 * 90
	nMaxStakeSearchInterval = int64(60)
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

	var coinStakeTx *wire.MsgTx
	//TODO(mably) static int64 nLastCoinStakeSearchTime = GetAdjustedTime();  // only initialized at startup
	var nLastCoinStakeSearchTime int64 = time.Now().Unix()
	var nLastCoinStakeSearchInterval int64 = 0

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

		var err error

		bits, err := m.wallet.chainSvr.CurrentProofOfStakeTarget()
		if err != nil {
			log.Warnf("CurrentProofOfStakeTarget error:\n %v", err)
			time.Sleep(time.Millisecond * 500)
			continue
		}

		nSearchTime := time.Now().Unix()

		coinStakeTx, err = m.wallet.CreateCoinStake(bits,
			nSearchTime, nSearchTime-nLastCoinStakeSearchTime)
		if err != nil {
			log.Warnf("CoinStake error:\n %v", err)
			time.Sleep(time.Millisecond * 500)
			continue
		}
		if coinStakeTx != nil {
			m.wallet.chainSvr.SendCoinStakeTransaction(coinStakeTx)
		}

		nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime
		nLastCoinStakeSearchTime = nSearchTime

		log.Tracef("nLastCoinStakeSearchInterval: %v", nLastCoinStakeSearchInterval)

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

func (w *Wallet) CreateCoinStake(bits uint32, nSearchTime int64, nSearchInterval int64) (coinStakeTx *wire.MsgTx, err error) {

	// Get current block's height and hash.
	bs, err := w.chainSvr.BlockStamp()
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

	nStakeMinAge := params.StakeMinAge
	StakeMinAmount, _ := btcutil.NewAmount(1.0)

	var fKernelFound bool = false
	var foundStake wtxmgr.Credit
	var csTxTime int64

	for _, eligible := range eligibles {
		if w.ShuttingDown() {
			return
		}
		var block *wtxmgr.BlockMeta
		block = &eligible.BlockMeta
		if eligible.Amount < StakeMinAmount {
			continue // only count coins meeting min amount requirement
		}
		if block.Time.Unix()+nStakeMinAge > nSearchTime-nMaxStakeSearchInterval {
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
				w.TxStore.UpdateBlockMeta(block)
			}
		}

		//for (unsigned int n=0; n<min(nSearchInterval,(int64)nMaxStakeSearchInterval) && !fKernelFound; n++)
		for n := int64(0); n < minInt64(nSearchInterval, nMaxStakeSearchInterval) && !fKernelFound; n++ {
			if w.ShuttingDown() {
				return
			}
			stpl := umint.StakeKernelTemplate{
				//BlockFromTime:  int64(utx.BlockTime),
				BlockFromTime: block.Time.Unix(),
				//StakeModifier:  utx.StakeModifier,
				StakeModifier: block.KernelStakeModifier,
				//PrevTxOffset:   utx.OffsetInBlock,
				PrevTxOffset: eligible.Offset,
				//PrevTxTime:     int64(utx.Time),
				PrevTxTime: eligible.Received.Unix(),
				//PrevTxOutIndex: outPoint.Index,
				PrevTxOutIndex: eligible.OutPoint.Index,
				//PrevTxOutValue: int64(utx.Value),
				PrevTxOutValue: int64(eligible.Amount),
				IsProtocolV03:  true,
				StakeMinAge:    nStakeMinAge,
				Bits:           bits,
				TxTime:         nSearchTime - n,
			}
			// https://github.com/ppcoin/ppcoin/blob/develop/src/wallet.cpp#L1419
			var success bool
			_, success, err, _ = umint.CheckStakeKernelHash(&stpl)
			if err != nil {
				log.Errorf("Check kernel hash error: %v", err)
				return
			}
			if success {
				log.Infof("Valid kernel hash found!")
				log.Tracef("Eligible Hash: %v", eligible.Hash.String())
				log.Tracef("Eligible Time: %v", eligible.Received)
				log.Tracef("Eligible Offset: %v", eligible.Offset)
				log.Tracef("Eligible OP Idx: %v", eligible.OutPoint.Index)
				log.Tracef("Eligible Amount: %v", eligible.Amount)
				log.Tracef("Eligible Block StakeModifier: %v", block.KernelStakeModifier)
				foundStake = eligible
				csTxTime = nSearchTime - n
				fKernelFound = true
				break
			}
		}
		if fKernelFound {
			break
		}
	}

	if fKernelFound {
		if w.Manager.IsLocked() {
			err = errors.New(
				"Valid kernel hash was found but manager is locked!")
		} else {
			coinStakeTx, err = w.createCoinstakeTx(
				foundStake, csTxTime, eligibles)
		}
	}

	return
}

// createCoinstakeTx returns a coinstake transaction paying an appropriate subsidy
// based on the passed block height to the provided address.
func (w *Wallet) createCoinstakeTx(stake wtxmgr.Credit, txTime int64, eligibles []wtxmgr.Credit) (*wire.MsgTx, error) {

	var err error

	var pkScript []byte
	pkScript = stake.PkScript

	var scriptClass txscript.ScriptClass
	var addrs []btcutil.Address
	scriptClass, addrs, _, err =
		txscript.ExtractPkScriptAddrs(pkScript, w.chainParams)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("failed to find a valid address")
	}

	switch scriptClass {
	case txscript.PubKeyTy:
	case txscript.PubKeyHashTy:
		addr := addrs[0]
		address, err := w.Manager.Address(addr)
		if err != nil {
			return nil, err
		}
		pka, ok := address.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			return nil, errors.New("address is not a pubkey address")
		}
		pkAddr, err := btcutil.NewAddressPubKey(
			pka.PubKey().SerializeUncompressed(), w.chainParams)
		if err != nil {
			return nil, err
		}
		pkScript, err = txscript.PayToAddrScript(pkAddr)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("no support for kernel type=%v", scriptClass)
	}

	lastPOWReward, err := w.chainSvr.Client.GetLastProofOfWorkReward()
	if err != nil {
		return nil, err
	}
	nCombineThreshold := btcutil.Amount(lastPOWReward / 3)
	//nCombineThreshold = GetProofOfWorkReward(
	//	GetLastBlockIndex(pindexBest, false)->nBits, w.chainParams) / 3

	selectedCredits := make([]wtxmgr.Credit, 0, len(eligibles))

	nBalance, err := w.CalculateBalance(6)
	nReserveBalance := btcutil.Amount(0)
	nCredit := btcutil.Amount(0)

	coinStakeTx := wire.NewMsgTx()

	coinStakeTx.Time = time.Unix(txTime, 0) // coinStakeTx.nTime -= n;

	//coinStakeTx.vout.push_back(CTxOut(0, scriptEmpty));
	coinStakeTx.AddTxOut(&wire.TxOut{
		Value:    0,
		PkScript: []byte{}, //TODO(mably) empty byte array or nil?
	})

	//coinStakeTx.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));
	coinStakeTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: stake.OutPoint,
	})

	selectedCredits = append(selectedCredits, stake) //vwtxPrev.push_back(pcoin.first);

	//coinStakeTx.vout.push_back(CTxOut(0, scriptPubKeyOut));
	coinStakeTx.AddTxOut(&wire.TxOut{
		Value:    0,
		PkScript: pkScript,
	})
	stakeBlock := stake.BlockMeta
	//if (header.GetBlockTime() + nStakeSplitAge > coinStakeTx.nTime)
	if stakeBlock.Time.Unix()+nStakeSplitAge > coinStakeTx.Time.Unix() {
		//coinStakeTx.vout.push_back(CTxOut(0, scriptPubKeyOut)); //split stake
		coinStakeTx.AddTxOut(&wire.TxOut{
			Value:    0,
			PkScript: pkScript,
		})
	}

	nCredit += stake.Amount // nCredit += pcoin.first->vout[pcoin.second].nValue;

	for _, eligible := range eligibles {

		// Attempt to add more inputs if no split stake
		if len(coinStakeTx.TxOut) == 2 && !eligible.Hash.IsEqual(&stake.Hash) {
			// Only add coins of the same key/address as kernel TODO(mably)
			//&& ((pcoin.first->vout[pcoin.second].scriptPubKey == scriptPubKeyKernel || pcoin.first->vout[pcoin.second].scriptPubKey == coinStakeTx.vout[1].scriptPubKey))

			// Stop adding more inputs if already too many inputs
			if len(coinStakeTx.TxIn) >= 100 { // if (coinStakeTx.vin.size() >= 100)
				break
			}
			// Stop adding more inputs if value is already pretty significant
			if nCredit > nCombineThreshold { // (nCredit > nCombineThreshold)
				break
			}
			// Stop adding inputs if reached reserve limit
			if eligible.Amount > nBalance-nReserveBalance { //(nCredit + pcoin.first->vout[pcoin.second].nValue > nBalance - nReserveBalance)
				break
			}
			// Do not add additional significant input
			if eligible.Amount > nCombineThreshold { //(pcoin.first->vout[pcoin.second].nValue > nCombineThreshold)
				continue
			}
			// Do not add input that is still too young
			if eligible.Received.Add(time.Second * time.Duration(blockchain.StakeMaxAge)).After(coinStakeTx.Time) { //(pcoin.first->nTime + STAKE_MAX_AGE > coinStakeTx.nTime)
				continue
			}

			coinStakeTx.AddTxIn(&wire.TxIn{
				PreviousOutPoint: eligible.OutPoint,
			})

			//nCredit += pcoin.first->vout[pcoin.second].nValue;
			nCredit += eligible.Amount

			//vwtxPrev.push_back(pcoin.first);
			selectedCredits = append(selectedCredits, eligible)
		}
	}

	// Calculate coin age reward
	nCoinAge, err := getCoinAge(coinStakeTx, selectedCredits, w.chainParams)
	if err != nil {
		return nil, err
	}

	log.Infof("Coin age : %v", nCoinAge)

	nCredit += blockchain.PPCGetProofOfStakeReward(int64(nCoinAge))

	log.Infof("Credit : %v", nCredit)

	var nMinFee int64 = 0
out:
	for {
		// Set output amount
		if len(coinStakeTx.TxOut) == 3 {
			coinStakeTx.TxOut[1].Value = ((int64(nCredit) - nMinFee) / 2 / blockchain.Cent) * blockchain.Cent
			coinStakeTx.TxOut[2].Value = int64(nCredit) - nMinFee - coinStakeTx.TxOut[1].Value
		} else {
			coinStakeTx.TxOut[1].Value = int64(nCredit) - nMinFee
		}

		// Sign
		w.signSelectedCredits(coinStakeTx, selectedCredits)

		// Limit size
		nBytes := coinStakeTx.SerializeSize()
		if nBytes >= wire.MaxBlockPayloadGen/5 {
			return nil, errors.New("CreateCoinStake : exceeded coinstake size limit")
		}

		// Check enough fee is paid
		if nMinFee < blockchain.GetMinFee(coinStakeTx)-blockchain.MinTxFee {
			nMinFee = blockchain.GetMinFee(coinStakeTx) - blockchain.MinTxFee
			continue // try signing again
		} else {
			break out
		}
	}

	return coinStakeTx, nil
}

func (w *Wallet) signSelectedCredits(msgTx *wire.MsgTx, eligibles []wtxmgr.Credit) error {

	// Set up our callbacks that we pass to txscript so it can
	// look up the appropriate keys and scripts by address.
	getKey := txscript.KeyClosure(func(addr btcutil.Address) (
		*btcec.PrivateKey, bool, error) {
		address, err := w.Manager.Address(addr)
		if err != nil {
			return nil, false, err
		}

		pka, ok := address.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			return nil, false, errors.New("address is not " +
				"a pubkey address")
		}

		key, err := pka.PrivKey()
		if err != nil {
			return nil, false, err
		}

		return key, pka.Compressed(), nil
	})

	getScript := txscript.ScriptClosure(func(
		addr btcutil.Address) ([]byte, error) {
		address, err := w.Manager.Address(addr)
		if err != nil {
			return nil, err
		}
		sa, ok := address.(waddrmgr.ManagedScriptAddress)
		if !ok {
			return nil, errors.New("address is not a script" +
				" address")
		}

		return sa.Script()
	})

	// All args collected. Now we can sign all the inputs that we can.
	// `complete' denotes that we successfully signed all outputs and that
	// all scripts will run to completion. This is returned as part of the
	// reply.
	complete := true
	for i, eligible := range eligibles {
		txIn := msgTx.TxIn[i]
		input := eligible.PkScript

		script, err := txscript.SignTxOutput(w.chainParams,
			msgTx, i, input, txscript.SigHashAll, getKey,
			getScript, txIn.SignatureScript)
		// Failure to sign isn't an error, it just means that
		// the tx isn't complete.
		if err != nil {
			complete = false
			continue
		}
		msgTx.TxIn[i].SignatureScript = script

		// Either it was already signed or we just signed it.
		// Find out if it is completely satisfied or still needs more.
		engine, err := txscript.NewEngine(
			input, msgTx, i, txscript.StandardVerifyFlags)
		if err != nil || engine.Execute() != nil {
			complete = false
		}
	}

	if complete {
		return nil
	} else {
		return errors.New("incomplete!")
	}
}

// ppc:
func getCoinAge(tx *wire.MsgTx, eligibles []wtxmgr.Credit, chainParams *chaincfg.Params) (uint64, error) {

	bnCentSecond := big.NewInt(0) // coin age in the unit of cent-seconds

	nTime := tx.Time

	for _, eligible := range eligibles {
		txPrevTime := eligible.Received
		if nTime.Before(txPrevTime) {
			err := fmt.Errorf("Transaction timestamp violation")
			return 0, err // Transaction timestamp violation
		}
		txPrevBlock := eligible.BlockMeta
		if txPrevBlock.Time.Add(time.Duration(chainParams.StakeMinAge) * time.Second).After(nTime) {
			continue // only count coins meeting min age requirement
		}

		nValueIn := int64(eligible.Amount)
		bnCentSecond.Add(bnCentSecond,
			new(big.Int).Div(new(big.Int).Mul(big.NewInt(nValueIn), big.NewInt((nTime.Unix()-txPrevTime.Unix()))),
				big.NewInt(blockchain.Cent)))
		log.Tracef("coin age nValueIn=%v nTimeDiff=%v bnCentSecond=%v", nValueIn, nTime.Unix()-txPrevTime.Unix(), bnCentSecond.String())
	}

	bnCoinDay := new(big.Int).Div(new(big.Int).Mul(bnCentSecond, big.NewInt(blockchain.Cent)),
		big.NewInt(int64(blockchain.Coin)*24*60*60))
	log.Tracef("coin age bnCoinDay=%v", bnCoinDay.String())

	return bnCoinDay.Uint64(), nil
}

// TODO: ppc: btcwallet findEligibleOutputs method filters by account
func (w *Wallet) ppcFindEligibleOutputs(minconf int32, bs *waddrmgr.BlockStamp) ([]wtxmgr.Credit, error) {
	unspent, err := w.TxStore.UnspentOutputs()
	if err != nil {
		return nil, err
	}

	// TODO: Eventually all of these filters (except perhaps output locking)
	// should be handled by the call to UnspentOutputs (or similar).
	// Because one of these filters requires matching the output script to
	// the desired account, this change depends on making wtxmgr a waddrmgr
	// dependancy and requesting unspent outputs for a single account.
	eligible := make([]wtxmgr.Credit, 0, len(unspent))
	for i := range unspent {
		output := &unspent[i]

		// Only include this output if it meets the required number of
		// confirmations.  Coinbase transactions must have have reached
		// maturity before their outputs may be spent.
		if !confirmed(minconf, output.Height, bs.Height) {
			continue
		}
		if output.FromCoinBase || output.FromCoinStake { // ppc:
			target := int32(w.chainParams.CoinbaseMaturity)
			if !confirmed(target, output.Height, bs.Height) {
				continue
			}
		}

		// Locked unspent outputs are skipped.
		if w.LockedOutpoint(output.OutPoint) {
			continue
		}

		// Filter out unspendable outputs, that is, remove those that
		// (at this time) are not P2PKH outputs.  Other inputs must be
		// manually included in transactions and sent (for example,
		// using createrawtransaction, signrawtransaction, and
		// sendrawtransaction).
		class, _, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, w.chainParams)
		if err != nil || class != txscript.PubKeyHashTy {
			continue
		}

		eligible = append(eligible, *output)
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

	posTarget, err := w.chainSvr.CurrentProofOfStakeTarget()
	if err != nil {
		return
	}

	if diff != 0 {
		posTarget = umint.BigToCompact(ppcutil.DifficultyToTarget(diff))
	}

	log.Infof("Required difficulty: %v (%v)",
		ppcutil.TargetToDifficulty(posTarget), posTarget)

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
		var block *wtxmgr.BlockMeta
		block = &eligible.BlockMeta
		if eligible.Amount < StakeMinAmount {
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
				w.TxStore.UpdateBlockMeta(block)
			}
		}

		scriptClass, addresses, _, _ := txscript.ExtractPkScriptAddrs(
			eligible.PkScript, w.chainParams)
		log.Infof("Addresses: %v (%v)", addresses, scriptClass)

		log.Infof("CHECK %v PPCs from %v https://bkchain.org/ppc/tx/%v#o%v",
			float64(eligible.Amount)/1000000.0,
			time.Unix(int64(eligible.Received.Unix()), 0).Format("2006-01-02"),
			eligible.OutPoint.Hash, eligible.OutPoint.Index)

		stpl := umint.StakeKernelTemplate{
			//BlockFromTime:  int64(utx.BlockTime),
			BlockFromTime: block.Time.Unix(),
			//StakeModifier:  utx.StakeModifier,
			StakeModifier: block.KernelStakeModifier,
			//PrevTxOffset:   utx.OffsetInBlock,
			PrevTxOffset: eligible.Offset,
			//PrevTxTime:     int64(utx.Time),
			PrevTxTime: eligible.Received.Unix(),
			//PrevTxOutIndex: outPoint.Index,
			PrevTxOutIndex: eligible.OutPoint.Index,
			//PrevTxOutValue: int64(utx.Value),
			PrevTxOutValue: int64(eligible.Amount),
			IsProtocolV03:  true,
			StakeMinAge:    nStakeMinAge,
			Bits:           posTarget,
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

func minInt64(a int64, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
