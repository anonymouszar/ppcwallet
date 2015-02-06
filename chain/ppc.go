// Copyright (c) 2014-2014 PPCD developers.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chain

import (
	"errors"

	"github.com/ppcsuite/ppcd/chaincfg"
)

func (c *Client) Params() (*chaincfg.Params, error) {
	return c.chainParams, nil
}

func (c *Client) CurrentTarget() (uint32, error) {
	select {
	case tgt := <-c.currentTarget:
		return tgt, nil
	case <-c.quit:
		return 0, errors.New("disconnected")
	}
}
