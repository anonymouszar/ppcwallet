// Copyright (c) 2014-2014 PPCD developers.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"time"

	"github.com/ppcsuite/ppcd/btcjson"
	"github.com/ppcsuite/ppcwallet/chain"
	"github.com/ppcsuite/ppcwallet/wallet"
)

// FindStake handles... TODO
func FindStake(w *wallet.Wallet, chainSvr *chain.Client, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*btcjson.FindStakeCmd)

	maxTime := cmd.MaxTime
	if maxTime == nil {
		in21days := time.Now().Unix() + (21 * 24 * 60 * 60) // 21 days
		maxTime = &in21days
	}
	difficulty := cmd.Difficulty
	if difficulty == nil {
		difficultyResult, err := chainSvr.GetDifficulty()
		if err != nil {
			return nil, err
		}
		difficulty = &difficultyResult.ProofOfStake
	}

	foundStakes, err := w.FindStake(*maxTime, *difficulty)
	if err != nil {
		return nil, err
	}

	stakesResult := []btcjson.FindStakeResult{}
	for _, foundStake := range foundStakes {
		jsonResult := btcjson.FindStakeResult{
			Difficulty: foundStake.Difficulty,
			Time:       foundStake.Time,
		}
		stakesResult = append(stakesResult, jsonResult)
	}

	return stakesResult, nil
}
