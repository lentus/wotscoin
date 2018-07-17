package utxo

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/lentus/wotscoin/lib/btc"
	"github.com/lentus/wotscoin/lib/others/sys"
	"io/ioutil"
	"os"
	"sync"
	"time"
)

const (
	UTXO_RECORDS_PREALLOC = 25e6
	UPKH_RECORDS_PREALLOC = 10e6
)

var (
	UTXO_WRITING_TIME_TARGET = 4 * time.Minute // Take it easy with flushing UTXO.db onto disk
)

type FunctionWalkUnspent func(*UtxoRec)

type CallbackFunctions struct {
	// If NotifyTx is set, it will be called each time a new unspent
	// output is being added or removed. When being removed, btc.TxOut is nil.
	NotifyTxAdd func(*UtxoRec)
	NotifyTxDel func(*UtxoRec, []bool)
}

type UpkhUndoRec struct {
	Deleted *UpkhRec
	Added   [][32]byte
}

// Used to pass block's changes to UnspentDB
type BlockChanges struct {
	Height          uint32
	LastKnownHeight uint32 // put here zero to disable this feature
	AddList         []*UtxoRec
	DeledTxs        map[[32]byte][]bool
	UndoData        map[[32]byte]*UtxoRec

	// UPKH changes
	AddUpkhList  []*UpkhRec
	DeleteUpkhs  [][32]byte
	UndoUpkhData []*UpkhUndoRec
}

type UnspentDB struct {
	HashMap map[UtxoKeyType][]byte
	sync.RWMutex // used to access HashMap

	upkhMap   map[UtxoKeyType][]byte
	upkhMutex sync.RWMutex // Used to access upkhMap

	LastBlockHash      []byte
	LastBlockHeight    uint32
	dir_utxo, dir_undo string
	volatimemode       bool
	UnwindBufLen       uint32
	DirtyDB            sys.SyncBool
	sync.Mutex

	abortwritingnow   chan bool
	WritingInProgress sys.SyncBool
	writingDone       sync.WaitGroup
	lastFileClosed    sync.WaitGroup

	CurrentHeightOnDisk uint32
	hurryup             chan bool
	DoNotWriteUndoFiles bool
	CB                  CallbackFunctions
}

type NewUnspentOpts struct {
	Dir             string
	Rescan          bool
	VolatimeMode    bool
	UnwindBufferLen uint32
	CB              CallbackFunctions
	AbortNow        *bool
}

func NewUnspentDb(opts *NewUnspentOpts) (db *UnspentDB) {
	//var maxbl_fn string
	db = new(UnspentDB)
	db.dir_utxo = opts.Dir
	db.dir_undo = db.dir_utxo + "undo" + string(os.PathSeparator)
	db.volatimemode = opts.VolatimeMode
	db.UnwindBufLen = 256
	db.CB = opts.CB
	db.abortwritingnow = make(chan bool, 1)
	db.hurryup = make(chan bool, 1)

	os.MkdirAll(db.dir_undo, 0770)

	os.Remove(db.dir_undo + "tmp")
	os.Remove(db.dir_utxo + "UTXO.db.tmp")

	if opts.Rescan {
		db.HashMap = make(map[UtxoKeyType][]byte, UTXO_RECORDS_PREALLOC)
		db.upkhMap = make(map[UtxoKeyType][]byte, UPKH_RECORDS_PREALLOC)
		return
	}

	// Load data form disk
	var k UtxoKeyType
	var cnt_dwn, cnt_dwn_from, perc int
	var le uint64
	var u64, tot_recs uint64
	var info string
	var rd *bufio.Reader
	var of *os.File

	fname := "UTXO.db"

redo:
	of, er := os.Open(db.dir_utxo + fname)
	if er != nil {
		goto fatal_error
	}

	rd = bufio.NewReaderSize(of, 0x100000)

	er = binary.Read(rd, binary.LittleEndian, &u64)
	if er != nil {
		goto fatal_error
	}
	db.LastBlockHeight = uint32(u64)

	db.LastBlockHash = make([]byte, 32)
	_, er = rd.Read(db.LastBlockHash)
	if er != nil {
		goto fatal_error
	}

	for recType := 0; recType < 2; recType++ {
		er = binary.Read(rd, binary.LittleEndian, &u64)
		if er != nil {
			goto fatal_error
		}

		//fmt.Println("Last block height", db.LastBlockHeight, "   Number of records", u64)
		cnt_dwn_from = int(u64 / 100)
		perc = 0

		if recType == 0 {
			db.HashMap = make(map[UtxoKeyType][]byte, int(u64))
			info = fmt.Sprint("\rLoading ", u64, " transactions from ", fname, " - ")
		} else {
			db.upkhMap = make(map[UtxoKeyType][]byte, int(u64))
			info = fmt.Sprint("\rLoading ", u64, " unused public key hashes from ", fname, " - ")
		}

		for tot_recs = 0; tot_recs < u64; tot_recs++ {
			if opts.AbortNow != nil && *opts.AbortNow {
				break
			}
			le, er = btc.ReadVLen(rd)
			if er != nil {
				goto fatal_error
			}

			er = btc.ReadAll(rd, k[:])
			if er != nil {
				goto fatal_error
			}

			b := malloc(uint32(int(le) - UtxoIdxLen))
			er = btc.ReadAll(rd, b)
			if er != nil {
				goto fatal_error
			}

			// we don't lock RWMutex here as this code is only used during init phase, when no other routines are running
			if recType == 0 {
				db.HashMap[k] = b
			} else {
				db.upkhMap[k] = b
			}

			if cnt_dwn == 0 {
				fmt.Print(info, perc, "% complete ... ")
				perc++
				cnt_dwn = cnt_dwn_from
			} else {
				cnt_dwn--
			}
		}

		fmt.Print("\r                                                              \r")
	}
	of.Close()

	//fmt.Print("\r                                                              \r")

	db.CurrentHeightOnDisk = db.LastBlockHeight

	return

fatal_error:
	if of != nil {
		of.Close()
	}

	println(er.Error())
	if fname != "UTXO.old" {
		fname = "UTXO.old"
		goto redo
	}
	db.LastBlockHeight = 0
	db.LastBlockHash = nil
	db.HashMap = make(map[UtxoKeyType][]byte, UTXO_RECORDS_PREALLOC)
	db.upkhMap = make(map[UtxoKeyType][]byte, UPKH_RECORDS_PREALLOC)

	return
}

func (db *UnspentDB) save() {
	//var cnt_dwn, cnt_dwn_from, perc int
	var abort, hurryup, check_time bool
	var total_records, current_record, data_progress, time_progress int64

	os.Rename(db.dir_utxo+"UTXO.db", db.dir_utxo+"UTXO.old")
	data_channel := make(chan []byte, 100)
	exit_channel := make(chan bool, 1)

	start_time := time.Now()

	db.RWMutex.RLock()
	db.upkhMutex.RLock()

	total_records = int64(len(db.HashMap))

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint64(db.LastBlockHeight))
	buf.Write(db.LastBlockHash)
	binary.Write(buf, binary.LittleEndian, uint64(total_records))

	// The data is written in a separate process
	// so we can abort without waiting for disk.
	db.lastFileClosed.Add(1)
	go func(fname string) {
		of, er := os.Create(fname)
		if er != nil {
			println("Create file:", er.Error())
			return
		}

		var dat []byte
		var abort, exit bool

		for !exit || len(data_channel) > 0 {
			select {

			case dat = <-data_channel:
				if len(exit_channel) > 0 {
					if abort = <-exit_channel; abort {
						goto exit
					} else {
						exit = true
					}
				}
				of.Write(dat)

			case abort = <-exit_channel:
				if abort {
					goto exit
				} else {
					exit = true
				}
			}
		}
	exit:
		if abort {
			of.Close() // abort
			os.Remove(fname)
		} else {
			of.Close()
			os.Rename(fname, db.dir_utxo+"UTXO.db")
		}
		db.lastFileClosed.Done()
	}(db.dir_utxo + btc.NewUint256(db.LastBlockHash).String() + ".db.tmp")

	var activeMap map[UtxoKeyType][]byte
	for recType := 0; recType < 2; recType++ {
		if recType == 0 {
			activeMap = db.HashMap
		} else {
			activeMap = db.upkhMap
			// Write the len of this map
			total_records = int64(len(db.upkhMap))
			binary.Write(buf, binary.LittleEndian, uint64(total_records))
			// Reset data and time progress
			current_record = 0
			start_time = time.Now()
		}
		for k, v := range activeMap {
			if check_time {
				check_time = false
				data_progress = int64((current_record << 20) / total_records)
				time_progress = int64((time.Now().Sub(start_time) << 20) / UTXO_WRITING_TIME_TARGET)
				if data_progress > time_progress {
					select {
					case <-db.abortwritingnow:
						abort = true
						goto finito
					case <-db.hurryup:
						hurryup = true
					case <-time.After(time.Millisecond):
					}
				}
			}

			for len(data_channel) >= cap(data_channel) {
				select {
				case <-db.abortwritingnow:
					abort = true
					goto finito
				case <-db.hurryup:
					hurryup = true
				case <-time.After(time.Millisecond):
				}
			}

			btc.WriteVlen(buf, uint64(UtxoIdxLen+len(v)))
			buf.Write(k[:])
			buf.Write(v)
			if buf.Len() > 0x10000 {
				data_channel <- buf.Bytes()
				buf = new(bytes.Buffer)
			}

			if !hurryup {
				current_record++
				if (current_record & 0x3f) == 0 {
					check_time = true
				}
			}
		}
	}
finito:
	db.upkhMutex.RUnlock()
	db.RWMutex.RUnlock()

	if !abort && buf.Len() > 0 {
		data_channel <- buf.Bytes()
	}
	exit_channel <- abort

	if !abort {
		db.DirtyDB.Clr()
		//println("utxo written OK in", time.Now().Sub(start_time).String(), timewaits)
		db.CurrentHeightOnDisk = db.LastBlockHeight
	}
	db.WritingInProgress.Clr()
	db.writingDone.Done()
}

// Commit the given add/del transactions to UTXO and Unwind DBs
func (db *UnspentDB) CommitBlockTxs(changes *BlockChanges, blhash []byte) (e error) {
	undo_fn := fmt.Sprint(db.dir_undo, changes.Height)
	undoUpkhFn := fmt.Sprint(db.dir_undo, changes.Height, "upkh")

	db.Mutex.Lock()
	defer db.Mutex.Unlock()
	db.abortWriting()

	if changes.UndoData != nil {
		bu := new(bytes.Buffer)
		bu.Write(blhash)
		if changes.UndoData != nil {
			for _, xx := range changes.UndoData {
				bin := xx.Serialize(true)
				btc.WriteVlen(bu, uint64(len(bin)))
				bu.Write(bin)
			}
		}
		ioutil.WriteFile(db.dir_undo+"tmp", bu.Bytes(), 0666)
		os.Rename(db.dir_undo+"tmp", undo_fn)
	}

	if changes.UndoUpkhData != nil {
		buf := new(bytes.Buffer)
		for _, undoRec := range changes.UndoUpkhData {
			if undoRec.Deleted != nil {
				bin := undoRec.Deleted.Bytes()
				btc.WriteVlen(buf, uint64(len(bin)))
				buf.Write(bin)
			} else {
				btc.WriteVlen(buf, uint64(0))
			}

			for _, pubKeyHash := range undoRec.Added {
				buf.Write(pubKeyHash[:])
			}
		}
		ioutil.WriteFile(db.dir_undo+"tmp", buf.Bytes(), 0666)
		os.Rename(db.dir_undo+"tmp", undoUpkhFn)
	}

	db.commit(changes)

	if db.LastBlockHash == nil {
		db.LastBlockHash = make([]byte, 32)
	}
	copy(db.LastBlockHash, blhash)
	db.LastBlockHeight = changes.Height

	if changes.Height > db.UnwindBufLen {
		os.Remove(fmt.Sprint(db.dir_undo, changes.Height-db.UnwindBufLen))
		os.Remove(fmt.Sprint(db.dir_undo, changes.Height-db.UnwindBufLen, "upkh"))
	}

	db.DirtyDB.Set()
	return
}

func (db *UnspentDB) undoBlockUpkhs(dat []byte) {
	le, n := btc.VLen(dat)
	offset := le+n

	if le != 0 {
		undoRec := ReadUpkhRec(dat[n:offset])

		var ind UtxoKeyType
		copy(ind[:], undoRec.PubKeyHash[:])

		db.upkhMutex.Lock()
		db.upkhMap[ind] = undoRec.MapBytes()
		db.upkhMutex.Unlock()
	}

	for offset < len(dat) {
		var indDel UtxoKeyType
		copy(indDel[:], dat[offset:])
		offset += 32

		db.upkhMutex.Lock()
		delete(db.upkhMap, indDel)
		db.upkhMutex.Unlock()
	}
}

func (db *UnspentDB) UndoBlockTxs(bl *btc.Block, newhash []byte) {
	db.Mutex.Lock()
	defer db.Mutex.Unlock()
	db.abortWriting()

	for _, tx := range bl.Txs {
		lst := make([]bool, len(tx.TxOut))
		for i := range lst {
			lst[i] = true
		}
		db.del(tx.Hash.Hash[:], lst)
	}

	fn := fmt.Sprint(db.dir_undo, db.LastBlockHeight)
	var addback []*UtxoRec

	if _, er := os.Stat(fn); er != nil {
		fn += ".tmp"
	}

	dat, er := ioutil.ReadFile(fn)
	if er != nil {
		panic(er.Error())
	}

	// Read UPKH undo file immediately to avoid undoing UTXOs then failing,
	// resulting in undone UTXOs but unchanged UPKHs
	fnUpkh := fmt.Sprint(db.dir_undo, db.LastBlockHeight, "upkh")
	if _, er := os.Stat(fnUpkh); er != nil {
		fnUpkh += ".tmp"
	}

	datUpkh, er := ioutil.ReadFile(fnUpkh)
	if er != nil {
		fmt.Println("failed to read UPKH undo file ", fnUpkh, er)
		panic(er.Error())
	}

	off := 32 // skip the block hash
	for off < len(dat) {
		le, n := btc.VLen(dat[off:])
		off += n
		qr := FullUtxoRec(dat[off : off+le])
		off += le
		addback = append(addback, qr)
	}

	for _, tx := range addback {
		if db.CB.NotifyTxAdd != nil {
			db.CB.NotifyTxAdd(tx)
		}

		var ind UtxoKeyType
		copy(ind[:], tx.TxID[:])
		db.RWMutex.RLock()
		v := db.HashMap[ind]
		db.RWMutex.RUnlock()
		if v != nil {
			oldrec := NewUtxoRec(ind, v)
			for a := range tx.Outs {
				if tx.Outs[a] == nil {
					tx.Outs[a] = oldrec.Outs[a]
				}
			}
		}
		db.RWMutex.Lock()
		db.HashMap[ind] = malloc_and_copy(tx.Bytes())
		db.RWMutex.Unlock()
	}

	os.Remove(fn)

	db.undoBlockUpkhs(datUpkh)
	os.Remove(fnUpkh)

	db.LastBlockHeight--
	copy(db.LastBlockHash, newhash)
	db.DirtyDB.Set()
}

// Call it when the main thread is idle
func (db *UnspentDB) Idle() bool {
	if db.volatimemode {
		return false
	}

	db.Mutex.Lock()
	defer db.Mutex.Unlock()

	if db.DirtyDB.Get() && !db.WritingInProgress.Get() {
		db.WritingInProgress.Set()
		db.writingDone.Add(1)
		go db.save() // this one will call db.writingDone.Done()
		return true
	}

	return false
}

func (db *UnspentDB) HurryUp() {
	select {
	case db.hurryup <- true:
	default:
	}
}

// Flush the data and close all the files
func (db *UnspentDB) Close() {
	db.HurryUp()
	db.volatimemode = false
	db.Idle()
	db.writingDone.Wait()
	db.lastFileClosed.Wait()
}

// Get given unspent output
func (db *UnspentDB) UnspentGet(po *btc.TxPrevOut) (res *btc.TxOut) {
	var ind UtxoKeyType
	var v []byte
	copy(ind[:], po.Hash[:])

	db.RWMutex.RLock()
	v = db.HashMap[ind]
	db.RWMutex.RUnlock()
	if v != nil {
		res = OneUtxoRec(ind, v, po.Vout)
	}

	return
}

func (db *UnspentDB) UpkhGet(pkh [32]byte) (res *UpkhRec) {
	var ind UtxoKeyType
	copy(ind[:], pkh[:])

	db.upkhMutex.RLock()
	v := db.upkhMap[ind]
	db.upkhMutex.RUnlock()

	if v != nil {
		res = LoadUpkhRec(ind, v)
	}

	return res
}

// Returns true if gived TXID is in UTXO
func (db *UnspentDB) TxPresent(id *btc.Uint256) (res bool) {
	var ind UtxoKeyType
	copy(ind[:], id.Hash[:])
	db.RWMutex.RLock()
	_, res = db.HashMap[ind]
	db.RWMutex.RUnlock()
	return
}

func (db *UnspentDB) del(hash []byte, outs []bool) {
	var ind UtxoKeyType
	copy(ind[:], hash)
	db.RWMutex.RLock()
	v := db.HashMap[ind]
	db.RWMutex.RUnlock()
	if v == nil {
		return // no such txid in UTXO (just ignorde delete request)
	}
	rec := NewUtxoRec(ind, v)
	if db.CB.NotifyTxDel != nil {
		db.CB.NotifyTxDel(rec, outs)
	}
	var anyout bool
	for i, rm := range outs {
		if rm {
			rec.Outs[i] = nil
		} else if rec.Outs[i] != nil {
			anyout = true
		}
	}
	db.RWMutex.Lock()
	if anyout {
		db.HashMap[ind] = malloc_and_copy(rec.Bytes())
	} else {
		delete(db.HashMap, ind)
	}
	db.RWMutex.Unlock()
	free(v)
}

func (db *UnspentDB) commit(changes *BlockChanges) {
	// Now apply the unspent changes
	for _, rec := range changes.AddList {
		var ind UtxoKeyType
		copy(ind[:], rec.TxID[:])
		if db.CB.NotifyTxAdd != nil {
			db.CB.NotifyTxAdd(rec)
		}
		db.RWMutex.Lock()
		db.HashMap[ind] = malloc_and_copy(rec.Bytes())
		db.RWMutex.Unlock()
	}
	for _, rec := range changes.AddUpkhList {
		var ind UtxoKeyType
		copy(ind[:], rec.PubKeyHash[:])
		b := rec.MapBytes()

		db.upkhMutex.Lock()
		db.upkhMap[ind] = malloc_and_copy(b)
		db.upkhMutex.Unlock()

	}
	for k, v := range changes.DeledTxs {
		db.del(k[:], v)
	}
	for i := range changes.DeleteUpkhs {
		var ind UtxoKeyType
		copy(ind[:], changes.DeleteUpkhs[i][:])

		db.upkhMutex.Lock()
		delete(db.upkhMap, ind)
		db.upkhMutex.Unlock()
	}
}

func (db *UnspentDB) AbortWriting() {
	db.Mutex.Lock()
	db.abortWriting()
	db.Mutex.Unlock()
}

func (db *UnspentDB) abortWriting() {
	if db.WritingInProgress.Get() {
		db.abortwritingnow <- true
		db.writingDone.Wait()
		select {
		case <-db.abortwritingnow:
		default:
		}
	}
}

func (db *UnspentDB) UTXOStats() (s string) {
	var outcnt, sum, sumcb uint64
	var totdatasize, unspendable, unspendable_recs, unspendable_bytes uint64

	// UTXO stats
	db.RWMutex.RLock()

	lele := len(db.HashMap)

	for k, v := range db.HashMap {
		totdatasize += uint64(len(v) + 8)
		rec := NewUtxoRecStatic(k, v)
		var spendable_found bool
		for _, r := range rec.Outs {
			if r != nil {
				outcnt++
				sum += r.Value
				if rec.Coinbase {
					sumcb += r.Value
				}
				if len(r.PKScr) > 0 && r.PKScr[0] == 0x6a {
					unspendable++
					unspendable_bytes += uint64(8 + len(r.PKScr))
				} else {
					spendable_found = true
				}
			}
		}
		if !spendable_found {
			unspendable_recs++
		}
	}

	db.RWMutex.RUnlock()

	// UPKH stats
	db.upkhMutex.RLock()

	var upkhDataSize uint64
	lthMap := make(map[[20]byte]bool)

	upkhCount := len(db.upkhMap)
	for k, v := range db.upkhMap {
		upkhDataSize += uint64(len(v)+8)
		rec := LoadUpkhRec(k, v)
		lthMap[rec.LongTermHash] = true
	}
	lths := len(lthMap)

	db.upkhMutex.RUnlock()

	s = fmt.Sprintf("UPKH: %d records with %d different long-term pubkeys  TotalData: %.1fMB\n",
		upkhCount, lths, float64(upkhDataSize)/1e6)
	s += fmt.Sprintf("UNSPENT: %.8f BTC in %d outs from %d txs. %.8f BTC in coinbase.\n",
		float64(sum)/1e8, outcnt, lele, float64(sumcb)/1e8)
	s += fmt.Sprintf(" TotalData:%.1fMB  MaxTxOutCnt:%d  DirtyDB:%t  Writing:%t  Abort:%t\n",
		float64(totdatasize)/1e6, len(rec_outs), db.DirtyDB.Get(), db.WritingInProgress.Get(), len(db.abortwritingnow) > 0)
	s += fmt.Sprintf(" Last Block : %s @ %d\n", btc.NewUint256(db.LastBlockHash).String(),
		db.LastBlockHeight)
	s += fmt.Sprintf(" Unspendable outputs: %d (%dKB)  txs:%d\n",
		unspendable, unspendable_bytes>>10, unspendable_recs)

	return
}

// Return DB statistics
func (db *UnspentDB) GetStats() (s string) {
	db.RWMutex.RLock()
	hml := len(db.HashMap)
	db.RWMutex.RUnlock()

	s = fmt.Sprintf("UNSPENT: %d records. MaxTxOutCnt:%d  DirtyDB:%t  Writing:%t  Abort:%t\n",
		hml, len(rec_outs), db.DirtyDB.Get(), db.WritingInProgress.Get(), len(db.abortwritingnow) > 0)
	s += fmt.Sprintf(" Last Block : %s @ %d\n", btc.NewUint256(db.LastBlockHash).String(),
		db.LastBlockHeight)
	return
}

func (db *UnspentDB) PurgeUnspendable(all bool) {
	var unspendable_txs, unspendable_recs uint64
	db.Mutex.Lock()
	db.abortWriting()

	db.RWMutex.Lock()

	for k, v := range db.HashMap {
		rec := NewUtxoRecStatic(k, v)
		var spendable_found bool
		var record_removed uint64
		for idx, r := range rec.Outs {
			if r != nil {
				if len(r.PKScr) > 0 && r.PKScr[0] == 0x6a {
					unspendable_recs++
					if all {
						rec.Outs[idx] = nil
						record_removed++
					}
				} else {
					spendable_found = true
				}
			}
		}
		if !spendable_found {
			free(v)
			delete(db.HashMap, k)
			unspendable_txs++
		} else if record_removed > 0 {
			free(v)
			db.HashMap[k] = malloc_and_copy(rec.Serialize(false))
			unspendable_recs += record_removed
		}
	}
	db.RWMutex.Unlock()

	db.Mutex.Unlock()

	fmt.Println("Purged", unspendable_txs, "transactions and", unspendable_recs, "extra records")
}
