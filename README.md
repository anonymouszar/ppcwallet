ppcwallet
=========

[![Build Status](https://travis-ci.org/ppcsuite/ppcwallet.png?branch=mably)]
(https://travis-ci.org/ppcsuite/ppcwallet)
[![tip for next commit](http://peer4commit.com/projects/130.svg)](http://peer4commit.com/projects/130)

ppcwallet is a daemon handling bitcoin wallet functionality for a
single user.  It acts as both an RPC client to ppcd and an RPC server
for wallet clients and legacy RPC applications.  It is based on the
Conformal [btcwallet](https://github.com/ppcsuite/ppcwallet) code.

Public and private keys are derived using the heirarchical
deterministic format described by
[BIP0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
Unencrypted private keys are not supported and are never written to
disk.  btcwallet uses the
`m/44'/<coin type>'/<account>'/<branch>/<address index>`
HD path for all derived addresses, as described by
[BIP0044](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki).

Due to the sensitive nature of public data in a BIP0032 wallet,
btcwallet provides the option of encrypting not just private keys, but
public data as well.  This is intended to thwart privacy risks where a
wallet file is compromised without exposing all current and future
addresses (public keys) managed by the wallet. While access to this
information would not allow an attacker to spend or steal coins, it
does mean they could track all transactions involving your addresses
and therefore know your exact balance.  In a future release, public data
encryption will extend to transactions as well.

ppcwallet is not an SPV client and requires connecting to a local or
remote ppcd instance for asynchronous blockchain queries and
notifications over websockets.  Full ppcd installation instructions
can be found [here](https://github.com/ppcsuite/ppcd).  An alternative
SPV mode that is compatible with ppcd and Peercoin Core is planned for
a future release.

No release-ready graphical frontends currently exist, however the
proof-of-concept [btcgui](https://github.com/btcsuite/btcgui) project
shows some of the possibilities of btcwallet.  In the coming months a
new stable RPC API is planned, at which point a high quality graphical
frontend can be finished.

Mainnet support is currently disabled by default.  Use of btcwallet on
mainnet requires passing the `--mainnet` flag on the command line or
adding `mainnet=1` to the configuration file.  Mainnet will be enabled
by default in a future release after further database changes and
testing.

## Installation

### Build from Source

- Install Go according to the installation instructions here:
  http://golang.org/doc/install

- Run the following commands to obtain and install ppcwallet and all
  dependencies:
```bash
$ go get -u -v github.com/ppcsuite/ppcd/...
$ go get -u -v github.com/ppcsuite/ppcwallet/...
```

- ppcd and ppcwallet will now be installed in either ```$GOROOT/bin``` or
  ```$GOPATH/bin``` depending on your configuration.  If you did not already
  add to your system path during the installation, we recommend you do so now.

## Updating

### Build from Source

- Run the following commands to update ppcwallet, all dependencies, and install it:

```bash
$ go get -u -v github.com/ppcsuite/ppcd/...
$ go get -u -v github.com/ppcsuite/ppcwallet/...
```

## Getting Started

The follow instructions detail how to get started with ppcwallet
connecting to a localhost ppcd.

### Windows

### Linux/BSD/POSIX/Source

- Run the following command to start ppcd:

```bash
$ ppcd --testnet -u rpcuser -P rpcpass
```

- Run the following command to start ppcwallet:

```bash
$ ppcwallet -u rpcuser -P rpcpass
```

If everything appears to be working, it is recommended at this point to
copy the sample ppcd and ppcwallet configurations and update with your
RPC username and password.

```bash
$ cp $GOPATH/src/github.com/ppcsuite/ppcd/sample-btcd.conf ~/.ppcd/ppcd.conf
$ cp $GOPATH/src/github.com/ppcsuite/ppcwallet/sample-btcwallet.conf ~/.ppcwallet/ppcwallet.conf
$ $EDITOR ~/.ppcd/ppcd.conf
$ $EDITOR ~/.ppcwallet/ppcwallet.conf
```

## Client Usage

Clients wishing to use ppcwallet must connect to the `ws` endpoint
over a websocket connection.  Messages sent to ppcwallet over this
websocket are expected to follow the standard Bitcoin JSON API
(partially documented
[here](https://en.bitcoin.it/wiki/Original_Bitcoin_client/API_Calls_list)).
Websocket connections also enable additional API extensions and
JSON-RPC notifications (currently undocumented).  The ppcd packages
`btcjson` and `btcws` provide types and functions for creating and
JSON (un)marshaling these requests and notifications.

## Issue Tracker

The [integrated github issue tracker](https://github.com/ppcsuite/ppcwallet/issues)
is used for this project.

<!--## GPG Verification Key

All official release tags are signed by Conformal so users can ensure the code
has not been tampered with and is coming from Conformal.  To verify the
signature perform the following:

- Download the public key from the Conformal website at
  https://opensource.conformal.com/GIT-GPG-KEY-conformal.txt

- Import the public key into your GPG keyring:
  ```bash
  gpg --import GIT-GPG-KEY-conformal.txt
  ```

- Verify the release tag with the following command where `TAG_NAME` is a
  placeholder for the specific tag:
  ```bash
  git tag -v TAG_NAME
  ```
-->
## License

ppcwallet is licensed under the liberal ISC License.
