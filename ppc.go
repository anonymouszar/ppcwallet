// Copyright (c) 2014-2014 PPCD developers.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/ppcsuite/ppcd/btcjson/v2/btcjson"
	"github.com/ppcsuite/ppcwallet/chain"
	"github.com/ppcsuite/ppcwallet/wallet"
)

// FindStake handles... TODO
func FindStake(w *wallet.Wallet, chainSvr *chain.Client, icmd interface{}) (interface{}, error) {
	cmd := icmd.(*btcjson.FindStakeCmd)

	foundStakes, err := w.FindStake(cmd.MaxTime, cmd.Difficulty)
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
