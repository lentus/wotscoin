# Wotscoin
This repository contains the code accompanying my master thesis (*"Post-quantum 
blockchain using one-time signature chains"*) which describes the new post-quantum 
signature scheme XNYSS, designed specifically for use in blockchain technology. 
Wotscoin is a fork of [**Gocoin**](https://github.com/piotrnar/gocoin "Gocoin github page") with support for XNYSS-based addresses. 
The purpose of this code is to show how post-quantum security can be added to 
existing bitcoin implementations by using XNYSS. A standalone version of XNYSS 
is available [here](https://github.com/lentus/xnyss "XNYSS github page"). 

While the thesis describes the use of segregated witness, this was not implemented 
because of time restrictions. 

## Usage
The wallet and client can be build as described below. The wallet can be used to 
create XNYSS-based addresses (using the normal `wallet -l` command) and sign 
transactions for those addresses (using the normal `wallet -send` command). By 
default the wallet creates one-time addresses: to create long-term ones, uncomment 
the line `longterm=true` in the file *wallet.cfg*. 

When using long-term addresses, you can create a number of signatures right away, 
but after creating a few you need to confirm they have been adopted into the 
blockchain using a client (when attempting to sign you will get an error which 
says that no signature nodes are available). This is done as follows:

* Execute `wallet -unconfirmed` to obtain a file called *unconfirmed.txt*
* Move *unconfirmed.txt* to a client machine
* In the client text ui, execute `confirm /path/to/unconfirmed.txt`
* Move the resulting `confirmed.txt` created by the client back to the wallet
* Execute `wallet -confirm /path/to/confirmed.txt`

To see how many signatures can currently be created, execute `wallet -keystate`.

Finally, you can create backups of the XNYSS wallet key state using the command 
`wallet -backup`. **IMPORTANT** Using the backup command is the **ONLY** way to securely 
create a backup of your XNYSS wallet: restoring a full system backup can result in 
reuse of W-OTS+ private keys, which may allow an attacker to forge a signature and 
thus steal funds.

## XNYSS and Scripts
For reasons described in the thesis, XNYSS is used in combination with bitcoin's
multisig scripts. The wallet provided in this repository can only be used for the new 
XNYSS-based addresses: use the original Gocoin wallet to create and sign with 
regular secp256k1-based addresses.'

**Changed files**
* **wallet/**
    * **main.go** Added command-line options 
    * **wallet.go** Changed wallet creation and printing, added confirmation and backup functionality 
    * **signtx.go** Changed signing to use XNYSS multisig
    * **decode.go** Changed tx dump output
    * **config.go** Added configuration options
* **lib/btc/** 
    * **const.go** Increased max script element size to be able to push XNYSS signatures
    * **funcs.go** Add CHECKXNYSSMULTISIG opcode to sigop count
    * **multisig.go** Add code to create and parse XNYSS multisigs
    * **opcodes.go** Add CHECKXNYSSMULTISIG opcode (replacing OP_NOP1)
    * **script.go** Add CHECKXNYSSMULTISIG opcode to ScriptToText
    * **wallet.go** Create XNYSS-based private address in NewPrivateAddr
* **lib/script/**
    * **script.go** Add XNYSS multisig script verification
* **lib/xnyss/** 
    * New files, contains XNYSS source code
* **client/usif/textui/**
    * **command.go** Add command for confirmation of given public key hashes


## UPKH DB and Block Verification
A new record type was added to the UTXO database, being Unused Public Key Hash 
(UPKH) records. This database is kept to allow quick verification of signatures 
created for long-term XNYSS addresses (see the thesis for more details). These 
records are queried during script verification, and updated when a new block is 
accepted.

**Changed files**
* **lib/chain/**
    * **chain_accept.go** Record UPKH db changes (add new ones, remove used ones, create undo data)
* **lib/utxo/**
    * **unspent_db.go** Add UPKH handling, add UPKH entries to BlockChanges struct  
    * **upkh_rec** New file, specifies UPKH record
    
###The following is the original Gocoin README.

# About Gocoin

**Gocoin** is a full **Bitcoin** solution written in Go language (golang).

The software architecture is focused on maximum performance of the node
and cold storage security of the wallet.

The **client** (p2p node) is an application independent from the **wallet**.
It keeps the entire UTXO set in RAM, providing the best block processing performance on the market.
With a decent machine and a fast connection (e.g. 4 vCPUs from Google Cloud or Amazon AWS),
the node should sync the entire bitcoin block chain in less than 4 hours (as of chain height ~512000).

The **wallet** is designed to be used offline.
It is deterministic and password seeded.
As long as you remember the password, you do not need any backups ever.

# Requirements

## Hardware

**client**:

* 64-bit architecture OS and Go compiler.
* File system supporting files larger than 4GB.
* At least 15GB of system memory (RAM).


**wallet**:

* Any platform that you can make your Go (cross)compiler to build for (Raspberry Pi works).
* For security reasons make sure to use encrypted swap file (if there is a swap file).
* If you decide to store your password in a file, have the disk encrypted (in case it gets stolen).


## Operating System
Having hardware requirements met, any target OS supported by your Go compiler will do.
Currently that can be at least one of the following:

* Windows
* Linux
* OS X
* Free BSD

## Build environment
In order to build Gocoin yourself, you will need the following tools installed in your system:

* **Go** (version 1.8 or higher) - http://golang.org/doc/install
* **Git** - http://git-scm.com/downloads

If the tools mentioned above are all properly installed, you should be able to execute `go` and `git`
from your OS's command prompt without a need to specify full path to the executables.

### Linux

When building for Linux make sure to have `gcc` installed or delete file `lib/utxo/membind_linux.go`


# Getting sources

Use `go get` to fetch and install the source code files.
Note that source files get installed within your GOPATH folder.

	go get github.com/piotrnar/gocoin


# Building

## Client node
Go to the `client/` folder and execute `go build` there.


## Wallet
Go to the `wallet/` folder and execute `go build` there.


## Tools
Go to the `tools/` folder and execute:

	go build btcversig.go

Repeat the `go build` for each source file of the tool you want to build.

# Binaries

Windows or Linux (amd64) binaries can be downloaded from

 * https://sourceforge.net/projects/gocoin/files/?source=directory

Please note that the binaries are usually not up to date.
I strongly encourage everyone to build the binaries himself.

# Development
Although it is an open source project, I am sorry to inform you that I will not merge in any pull requests.
The reason is that I want to stay an explicit author of this software, to keep a full control over its
licensing. If you are missing some functionality, just describe me your needs and I will see what I can do
for you. But if you want your specific code in, please fork and develop your own repo.

# Support
The official web page of the project is served at <a href="http://gocoin.pl">gocoin.pl</a>
where you can find extended documentation, including **User Manual**.

Please do not log github issues when you only have questions concerning this software.
Instead see [Contact](http://gocoin.pl/gocoin_links.html) page at [gocoin.pl](http://gocoin.pl) website
for possible ways of contacting me.
