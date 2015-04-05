// Copyright (c) 2014-2014 PPCD developers.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/ppcsuite/ppcd/btcjson"
	"github.com/ppcsuite/ppcd/btcjson/btcws"
	"github.com/ppcsuite/ppcwallet/chain"
	"github.com/ppcsuite/ppcwallet/wallet"
)

// FindStake handles... TODO
func FindStake(w *wallet.Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcws.FindStakeCmd)

	foundStakes, err := w.FindStake(cmd.MaxTime, cmd.Difficulty)
	if err != nil {
		return nil, err
	}

	stakesResult := []btcws.FindStakeResult{}
	for _, foundStake := range foundStakes {
		jsonResult := btcws.FindStakeResult{
			Difficulty: foundStake.Difficulty,
			Time:       foundStake.Time,
		}
		stakesResult = append(stakesResult, jsonResult)
	}

	return stakesResult, nil
}
