// Copyright (c) 2014-2014 PPCD developers.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr

import (
	"bytes"
	"fmt"

	"github.com/ppcsuite/btcutil"
	"github.com/ppcsuite/ppcd/wire"
	"github.com/ppcsuite/ppcwallet/walletdb"
)

// UpdateBlockMeta
func (s *Store) UpdateBlockMeta(block *BlockMeta) error {
	return scopedUpdate(s.namespace, func(ns walletdb.Bucket) error {
		return s.updateBlockMeta(ns, block)
	})
}

// updateBlockMeta
func (s *Store) updateBlockMeta(ns walletdb.Bucket, block *BlockMeta) error {
	// Check for existing block record.
	blockKey, blockVal := existsBlockRecord(ns, block.Height)
	var err error
	if blockVal == nil {
		str := fmt.Sprintf("No block found in store for height %v", block.Height)
		err = storeError(ErrData, str, nil)
	} else {
		var newBlockVal []byte
		newBlockVal, err = updateBlockRecord(blockVal, block)
		if err == nil {
			err = putRawBlockRecord(ns, blockKey, newBlockVal)
		}
	}
	return err
}

// PPCNewTxRecordFromTx creates a new transaction record that may be inserted
// into the store.
func PPCNewTxRecordFromTx(tx *btcutil.Tx) (*TxRecord, error) {
	msgTx := tx.MsgTx()
	buf := bytes.NewBuffer(make([]byte, 0, msgTx.SerializeSize()))
	err := msgTx.Serialize(buf)
	if err != nil {
		str := "failed to serialize transaction"
		return nil, storeError(ErrInput, str, err)
	}
	rec := &TxRecord{
		MsgTx:        *msgTx,
		Offset:       tx.Offset(), // ppc:
		SerializedTx: buf.Bytes(),
	}
	copy(rec.Hash[:], wire.DoubleSha256(rec.SerializedTx))
	return rec, nil
}
