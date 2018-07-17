package main

import (
	"os"
	"fmt"
	"bufio"
	"bytes"
	"strings"
	"encoding/hex"
	"github.com/lentus/wotscoin/lib/btc"
	"github.com/lentus/wotscoin/lib/others/sys"
	"io/ioutil"
	"github.com/lentus/wotscoin/lib/xnyss"
	"encoding/binary"
)

var (
	type2_secret     []byte // used to type-2 wallets
	first_determ_idx int
	// set in make_wallet():
	keys        []*btc.PrivateAddr
	segwit      []*btc.BtcAddr
	curFee      uint64
	msAddresses []*btc.MultiSig
)

// load private keys fo .others file
func load_others() {
	f, e := os.Open(RawKeysFilename)
	if e == nil {
		defer f.Close()
		td := bufio.NewReader(f)
		for {
			li, _, _ := td.ReadLine()
			if li == nil {
				break
			}
			if len(li) == 0 {
				continue
			}
			pk := strings.SplitN(strings.Trim(string(li), " "), " ", 2)
			if pk[0][0] == '#' {
				continue // Just a comment-line
			}

			rec, er := btc.DecodePrivateAddr(pk[0])
			if er != nil {
				println("DecodePrivateAddr error:", er.Error())
				if *verbose {
					println(pk[0])
				}
				continue
			}
			if rec.Version != ver_secret() {
				println(pk[0][:6], "has version", rec.Version, "while we expect", ver_secret())
				fmt.Println("You may want to play with -t or -ltc switch")
			}
			if len(pk) > 1 {
				rec.BtcAddr.Extra.Label = pk[1]
			} else {
				rec.BtcAddr.Extra.Label = fmt.Sprint("Other ", len(keys))
			}
			keys = append(keys, rec)
		}
		if *verbose {
			fmt.Println(len(keys), "keys imported from", RawKeysFilename)
		}
	} else {
		if *verbose {
			fmt.Println("You can also have some dumped (b58 encoded) Key keys in file", RawKeysFilename)
		}
	}
}

// Get the secret seed and generate "keycnt" key pairs (both private and public)
func make_wallet() {
	var lab string

	load_others()

	var seed_key []byte
	var hdwal *btc.HDWallet

	defer func() {
		sys.ClearBuffer(seed_key)
		if hdwal != nil {
			sys.ClearBuffer(hdwal.Key)
			sys.ClearBuffer(hdwal.ChCode)
		}
	}()

	pass := getpass()
	if pass == nil {
		cleanExit(0)
	}

	if waltype >= 1 && waltype <= 3 {
		seed_key = make([]byte, 32)
		btc.ShaHash(pass, seed_key)
		sys.ClearBuffer(pass)
		lab = fmt.Sprintf("Typ%c", 'A'+waltype-1)
		if waltype == 1 {
			println("WARNING: Wallet Type 1 is obsolete")
		} else if waltype == 2 {
			if type2sec != "" {
				d, e := hex.DecodeString(type2sec)
				if e != nil {
					println("t2sec error:", e.Error())
					cleanExit(1)
				}
				type2_secret = d
			} else {
				type2_secret = make([]byte, 20)
				btc.RimpHash(seed_key, type2_secret)
			}
		}
	} else if waltype == 4 {
		lab = "TypHD"
		hdwal = btc.MasterKey(pass, testnet)
		sys.ClearBuffer(pass)
	} else {
		sys.ClearBuffer(pass)
		println("ERROR: Unsupported wallet type", waltype)
		cleanExit(1)
	}

	if longterm {
		fmt.Println("Generating", keycnt, "LONG-TERM addresses...")
	} else {
		fmt.Println("Generating", keycnt, "ONE-TIME addresses...")
	}
	if *verbose {
		fmt.Println("Version", ver_script(), ",", mskeycnt, "key pairs per address")
	}

	first_determ_idx = len(keys)
	ms := btc.NewXNYSSMultiSig()
	for i := uint(0); i < keycnt*mskeycnt; i++ {
		prv_key := make([]byte, 32)
		if waltype == 3 {
			btc.ShaHash(seed_key, prv_key)
			seed_key = append(seed_key, byte(i))
		} else if waltype == 2 {
			seed_key = btc.DeriveNextPrivate(seed_key, type2_secret)
			copy(prv_key, seed_key)
		} else if waltype == 1 {
			btc.ShaHash(seed_key, prv_key)
			copy(seed_key, prv_key)
		} else /*if waltype==4*/ {
			// HD wallet
			_hd := hdwal.Child(uint32(0x80000000 | i))
			copy(prv_key, _hd.Key[1:])
			sys.ClearBuffer(_hd.Key)
			sys.ClearBuffer(_hd.ChCode)
		}

		rec := btc.NewPrivateAddr(prv_key, ver_secret(), longterm)

		if *pubkey != "" && *pubkey == rec.BtcAddr.String() {
			fmt.Println("Public address:", rec.BtcAddr.String())
			fmt.Println("Public hexdump:", hex.EncodeToString(rec.BtcAddr.Pubkey))
			return
		}

		// Load state file for this xnyss tree if it exists. If not, do nothing
		// since the new private address already contains a new state tree.
		state, err := ioutil.ReadFile("state/" + rec.StateFn)
		if err != nil && !os.IsNotExist(err) {
			fmt.Println("Error: Failed to open state file for address", rec.BtcAddr.String(), "-", err)
			continue
		}
		if state != nil {
			// Make sure that if we are loading existing state, the address mode
			// matches the runtime address mode.
			if state[0] == 0x01 && longterm {
				fmt.Println("Error: Trying to load one-time keys in long-term address mode")
				return
			} else if state[0] == 0x00 && !longterm {
				fmt.Println("Error: Trying to load long-term keys in one-time address mode")
				return
			}

			rec.TreeState, err = xnyss.Load(state)
			if err != nil {
				fmt.Println("Error: Failed to load state for address", rec.BtcAddr.String(), "-", err)
				continue
			}
		}

		rec.BtcAddr.Extra.Label = fmt.Sprint(lab, " ", (i+mskeycnt)/mskeycnt)
		keys = append(keys, rec)

		ms.PublicKeys = append(ms.PublicKeys, rec.Hash160[:])
		if uint(i+1)%mskeycnt == 0 {
			msAddresses = append(msAddresses, ms)
			ms = btc.NewXNYSSMultiSig()
		}
	}
	if *verbose {
		fmt.Println("Private keys re-generated")
	}

	// Calculate SegWit addresses
	segwit = make([]*btc.BtcAddr, len(keys))
	for i, pk := range keys {
		if len(pk.Pubkey) != 33 {
			continue
		}
		if *bech32_mode {
			segwit[i] = btc.NewAddrFromPkScript(append([]byte{0, 20}, pk.Hash160[:]...), testnet)
		} else {
			h160 := btc.Rimp160AfterSha256(append([]byte{0, 20}, pk.Hash160[:]...))
			segwit[i] = btc.NewAddrFromHash160(h160[:], btc.AddrVerScript(testnet))
		}
	}
}

// Print all the public addresses
func dump_addrs() {
	f, _ := os.Create("wallet.txt")

	var addrType string
	if longterm {
		addrType = "LONG-TERM"
	} else {
		addrType = "ONE-TIME"
	}
	fmt.Fprintln(f, "# Deterministic Wallet Type", waltype, "with", addrType, "addresses")
	if type2_secret != nil {
		fmt.Fprintln(f, "#", hex.EncodeToString(keys[first_determ_idx].BtcAddr.Pubkey))
		fmt.Fprintln(f, "#", hex.EncodeToString(type2_secret))
	}

	if !*noverify {
		for i := range keys {
			if er := btc.VerifyKeyPair(keys[i].Key, keys[i].BtcAddr.Pubkey); er != nil {
				println("Something wrong with key at index", i, " - abort!", er.Error())
				cleanExit(1)
			}
		}
	}

	for i := range msAddresses {
		var pubaddr string
		// TODO remove segwit code?
		if *segwit_mode {
			if segwit[i] == nil {
				pubaddr = "-=CompressedKey=-"
			} else {
				pubaddr = segwit[i].String()
			}
		}

		pubaddr = msAddresses[i].BtcAddr(testnet).String()
		fmt.Println(pubaddr, keys[i*int(mskeycnt)].BtcAddr.Extra.Label)
		if f != nil {
			fmt.Fprintln(f, pubaddr, keys[i*int(mskeycnt)].BtcAddr.Extra.Label)
		}
	}
	if f != nil {
		f.Close()
		fmt.Println("You can find all the addresses in wallet.txt file")
	}
}

func printKeyState() {
	fmt.Println("Printing key state for all address")

	var unconfirmed, available, msIdx int
	for i := range keys {
		unconfirmed += len(keys[i].TreeState.Unconfirmed())
		available += keys[i].TreeState.Available(nil)

		if (i+1)%int(mskeycnt) == 0 {
			if longterm {
				fmt.Printf("\n%s    %d sigs available (%d unconfirmed)",
					msAddresses[msIdx].BtcAddr(testnet).String(), available, unconfirmed)
			} else {
				var backups int
				var status string
				if available == int(mskeycnt) {
					backups = available - 1
					status = "AVAILABLE"
				} else {
					backups = available
					status = "USED"
				}

				fmt.Printf("\n%s    %s (%d backups left)",
					msAddresses[msIdx].BtcAddr(testnet).String(), status, backups)
			}

			unconfirmed = 0
			available = 0
			msIdx++
		}
	}
	fmt.Println()

	if longterm {
		fmt.Println("\nNote that you can sign multiple inputs in one transaction with just 1 signature slot")
	}
}

func write_unconfirmed() {
	f, err := os.Create("unconfirmed.txt")
	if err != nil {
		fmt.Println("Failed to create file unconfirmed.txt -", err)
		return
	}
	defer f.Close()

	var ctr uint32
	buf := new(bytes.Buffer)
	for _, key := range keys {
		for _, pkh := range key.TreeState.Unconfirmed() {
			buf.Write(pkh)
			ctr++
		}
	}

	binary.Write(f, binary.LittleEndian, ctr)
	f.Write(buf.Bytes())

	fmt.Println()
	fmt.Println("Wrote", ctr, "unconfirmed pubkey hashes to unconfirmed.txt")
	fmt.Println("Transfer it to a wotscoin client and use the 'confirm' command to create a confirm.txt file.")
	fmt.Println("Transfer confirm.txt back to this wallet, and use the 'confirm' flag to apply it.")
}

func confirm() {
	f, err := os.Open(*confirmPkhs)
	if err != nil {
		fmt.Println("Error: failed to open confirmation file ", *confirmPkhs, " -", err)
		return
	}
	defer f.Close()

	var amount uint32
	rd := bufio.NewReader(f)
	err = binary.Read(rd, binary.LittleEndian, &amount)
	if err != nil {
		fmt.Println("Error: failed to read amount of confirmation entries -", err)
		return
	}

	lth := make([]byte, 20)
	pkh := make([]byte, 32)
	successCount := 0
	fmt.Println("Processing confirmations...")
	for i := uint32(0); i < amount; i++ {
		_, err := rd.Read(lth)
		if err != nil {
			fmt.Println("Error: failed to read pubkey hash -", err)
			return
		}

		_, err = rd.Read(pkh)
		if err != nil {
			fmt.Println("Error: failed to read pubkey hash -", err)
			return
		}

		var confirms uint32
		err = binary.Read(rd, binary.LittleEndian, &confirms)
		if err != nil {
			fmt.Println("Error: failed to read confirmation count -", err)
			return
		}

		key := public_to_key(lth)
		if key == nil {
			fmt.Println("No key state found for long-term hash ", hex.EncodeToString(lth))
			continue
		}

		successCount++
		if confirms > uint32(xnyss.ConfirmsRequired) {
			key.TreeState.Confirm(pkh, xnyss.ConfirmsRequired)
		} else {
			key.TreeState.Confirm(pkh, uint8(confirms))
		}
	}

	fmt.Println()
	fmt.Println("Processed", amount, "confirmations,", successCount, "successfull")
}

func make_backup() {
	if !longterm {
		fmt.Println("Backing up keys is only applicable to long-term addresses")
		return
	}

	if _, err := os.Stat(BackupDirectory); err == nil || !os.IsNotExist(err) {
		fmt.Println("You have another backup in the ", BackupDirectory, " folder.")
		fmt.Println("Move it to a safe location, then try again")
		return
	}

	if err := os.Mkdir(BackupDirectory, os.ModePerm); err != nil {
		fmt.Println("Failed to create backup directory -", err)
		return
	}

	const minNodes = 5    // Must have created at least two signatures with a chain
	const backupCount = 2 // Take this many nodes from the original chain

	var addrCount, totalCount, msIdx int
	fmt.Println("Amount of available signatures per address to include in backup:")
	for i := range keys {
		if keys[i].TreeState.Available(nil) >= minNodes {
			addrCount += backupCount
			totalCount += backupCount
		}

		if (i+1)%int(mskeycnt) == 0 {
			fmt.Println(msAddresses[msIdx].BtcAddr(testnet).String(), ":", addrCount)

			addrCount = 0
			msIdx++
		}
	}

	if totalCount == 0 {
		fmt.Println()
		fmt.Println("No nodes to backup. Wait for more signatures to be confirmed.")
		fmt.Println("Backup canceled")
		return
	}

	fmt.Println()
	if !ask_yes_no("Are you sure you want to proceed?") {
		fmt.Println("Backup canceled")
		return
	}

	for i := range keys {
		var backupTree *xnyss.NYTree
		if keys[i].TreeState.Available(nil) >= minNodes {
			backupTree, _ = keys[i].TreeState.Backup(backupCount)
		} else {
			backupTree, _ = keys[i].TreeState.Backup(minNodes)
		}

		err := ioutil.WriteFile(BackupDirectory+"/"+keys[i].StateFn,
			backupTree.Bytes(), 0666)
		if err != nil {
			fmt.Println("Error: Failed to write backup state to file for key", i, ",", err)
		}
	}

	fmt.Println()
	fmt.Println("Finished creating backups in folder", BackupDirectory, ".")
	fmt.Println("Move the backup folder to a safe location.")
	fmt.Println("When using it as key state for a different device, remember to use the same password!")
}

func public_to_key(pubkey []byte) *btc.PrivateAddr {
	for i := range keys {
		if bytes.Equal(pubkey, keys[i].BtcAddr.Hash160[:]) {
			return keys[i]
		}
	}
	return nil
}

func hash_to_key_idx(h160 []byte) (res int) {
	for i := range keys {
		if bytes.Equal(keys[i].BtcAddr.Hash160[:], h160) {
			return i
		}
		if segwit[i] != nil && bytes.Equal(segwit[i].Hash160[:], h160) {
			return i
		}
	}
	return -1
}

func hash_to_key(h160 []byte) *btc.PrivateAddr {
	if i := hash_to_key_idx(h160); i >= 0 {
		return keys[i]
	}
	return nil
}

func address_to_key(addr string) *btc.PrivateAddr {
	a, e := btc.NewAddrFromString(addr)
	if e != nil {
		println("Cannot Decode address", addr)
		println(e.Error())
		cleanExit(1)
	}
	return hash_to_key(a.Hash160[:])
}

// suuports only P2KH scripts
func pkscr_to_key(scr []byte) *btc.PrivateAddr {
	if len(scr) == 25 && scr[0] == 0x76 && scr[1] == 0xa9 && scr[2] == 0x14 && scr[23] == 0x88 && scr[24] == 0xac {
		return hash_to_key(scr[3:23])
	}
	// P2SH(WPKH)
	if len(scr) == 23 && scr[0] == 0xa9 && scr[22] == 0x87 {
		return hash_to_key(scr[2:22])
	}
	// P2WPKH
	if len(scr) == 22 && scr[0] == 0x00 && scr[1] == 0x14 {
		return hash_to_key(scr[2:])
	}
	return nil
}

func dump_prvkey() {
	if *dumppriv == "*" {
		// Dump all private keys
		for i := range keys {
			fmt.Println(keys[i].String(), keys[i].BtcAddr.String(), keys[i].BtcAddr.Extra.Label)
		}
	} else {
		// single key
		k := address_to_key(*dumppriv)
		if k != nil {
			fmt.Println("Public address:", k.BtcAddr.String(), k.BtcAddr.Extra.Label)
			fmt.Println("Public hexdump:", hex.EncodeToString(k.BtcAddr.Pubkey))
			fmt.Println("Public compressed:", k.BtcAddr.IsCompressed())
			fmt.Println("Private encoded:", k.String())
			fmt.Println("Private hexdump:", hex.EncodeToString(k.Key))
		} else {
			println("Dump Private Key:", *dumppriv, "not found it the wallet")
		}
	}
}
