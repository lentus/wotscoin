package common

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/lentus/wotscoin/lib/btc"
	"github.com/lentus/wotscoin/lib/chain"
	"github.com/lentus/wotscoin/lib/others/sys"
	"github.com/lentus/wotscoin/lib/others/utils"
	"log"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ConfigFile = "gocoin.conf"
	Version    = uint32(70015)
	Services   = uint64(0x00000009)
)

var (
	LogBuffer = new(bytes.Buffer)
	Log *log.Logger = log.New(LogBuffer, "", 0)

	BlockChain   *chain.Chain
	GenesisBlock *btc.Uint256
	Magic        [4]byte
	Testnet      bool

	Last TheLastBlock

	GocoinHomeDir  string
	StartTime      time.Time
	MaxPeersNeeded int

	CounterMutex sync.Mutex
	Counter      map[string]uint64 = make(map[string]uint64)

	busyLine int32

	NetworkClosed sys.SyncBool

	AverageBlockSize sys.SyncInt

	allBalMinVal uint64

	DropSlowestEvery time.Duration
	BlockExpireEvery time.Duration
	PingPeerEvery    time.Duration

	UserAgent string

	ListenTCP bool

	minFeePerKB, routeMinFeePerKB, minminFeePerKB uint64
	maxMempoolSizeBytes, maxRejectedSizeBytes     uint64

	KillChan chan os.Signal = make(chan os.Signal)

	SecretKey []byte // 32 bytes of secret key
	PublicKey string

	WalletON       bool
	WalletProgress uint32 // 0 for not / 1000 for max
	WalletOnIn     uint32

	BlockChainSynchronized bool

	lastTrustedBlock       *btc.Uint256
	LastTrustedBlockHeight uint32
)

type TheLastBlock struct {
	sync.Mutex // use it for writing and reading from non-chain thread
	Block      *chain.BlockTreeNode
	time.Time
}

func (b *TheLastBlock) BlockHeight() (res uint32) {
	b.Mutex.Lock()
	res = b.Block.Height
	b.Mutex.Unlock()
	return
}

func CountSafe(k string) {
	CounterMutex.Lock()
	Counter[k]++
	CounterMutex.Unlock()
}

func CountSafeAdd(k string, val uint64) {
	CounterMutex.Lock()
	Counter[k] += val
	CounterMutex.Unlock()
}

func Busy() {
	var line int
	_, _, line, _ = runtime.Caller(1)
	atomic.StoreInt32(&busyLine, int32(line))
}

func BusyIn() int {
	return int(atomic.LoadInt32(&busyLine))
}

func BytesToString(val uint64) string {
	if val < 1e6 {
		return fmt.Sprintf("%.1f KB", float64(val)/1e3)
	} else if val < 1e9 {
		return fmt.Sprintf("%.2f MB", float64(val)/1e6)
	}
	return fmt.Sprintf("%.2f GB", float64(val)/1e9)
}

func NumberToString(num float64) string {
	if num > 1e24 {
		return fmt.Sprintf("%.2f Y", num/1e24)
	}
	if num > 1e21 {
		return fmt.Sprintf("%.2f Z", num/1e21)
	}
	if num > 1e18 {
		return fmt.Sprintf("%.2f E", num/1e18)
	}
	if num > 1e15 {
		return fmt.Sprintf("%.2f P", num/1e15)
	}
	if num > 1e12 {
		return fmt.Sprintf("%.2f T", num/1e12)
	}
	if num > 1e9 {
		return fmt.Sprintf("%.2f G", num/1e9)
	}
	if num > 1e6 {
		return fmt.Sprintf("%.2f M", num/1e6)
	}
	if num > 1e3 {
		return fmt.Sprintf("%.2f K", num/1e3)
	}
	return fmt.Sprintf("%.2f", num)
}

func HashrateToString(hr float64) string {
	return NumberToString(hr) + "H/s"
}

// Calculates average blocks size over the last "CFG.Stat.BSizeBlks" blocks
// Only call from blockchain thread.
func RecalcAverageBlockSize() {
	n := BlockChain.LastBlock()
	var sum, cnt uint
	for maxcnt := CFG.Stat.BSizeBlks; maxcnt > 0 && n != nil; maxcnt-- {
		sum += uint(n.BlockSize)
		cnt++
		n = n.Parent
	}
	if sum > 0 && cnt > 0 {
		AverageBlockSize.Store(int(sum / cnt))
	} else {
		AverageBlockSize.Store(204)
	}
}

func GetRawTx(BlockHeight uint32, txid *btc.Uint256) (data []byte, er error) {
	data, er = BlockChain.GetRawTx(BlockHeight, txid)
	if er != nil {
		if Testnet {
			data = utils.GetTestnetTxFromWeb(txid)
		} else {
			data = utils.GetTxFromWeb(txid)
		}
		if data != nil {
			er = nil
		} else {
			er = errors.New("GetRawTx and GetTxFromWeb failed for " + txid.String())
		}
	}
	return
}

func WalletPendingTick() (res bool) {
	mutex_cfg.Lock()
	if WalletOnIn > 0 && BlockChainSynchronized {
		WalletOnIn--
		res = WalletOnIn == 0
	}
	mutex_cfg.Unlock()
	return
}

// Make sure to call it with mutex_cfg locked
func ApplyLastTrustedBlock() {
	hash := btc.NewUint256FromString(CFG.LastTrustedBlock)
	lastTrustedBlock = hash
	LastTrustedBlockHeight = 0

	if BlockChain != nil {
		BlockChain.BlockIndexAccess.Lock()
		node := BlockChain.BlockIndex[hash.BIdx()]
		BlockChain.BlockIndexAccess.Unlock()
		if node != nil {
			LastTrustedBlockHeight = node.Height
			for node != nil {
				node.Trusted = true
				node = node.Parent
			}
		}
	}
}

func LastTrustedBlockMatch(h *btc.Uint256) (res bool) {
	mutex_cfg.Lock()
	res = lastTrustedBlock != nil && lastTrustedBlock.Equal(h)
	mutex_cfg.Unlock()
	return
}

func AcceptTx() (res bool) {
	mutex_cfg.Lock()
	res = CFG.TXPool.Enabled && BlockChainSynchronized
	mutex_cfg.Unlock()
	return
}
