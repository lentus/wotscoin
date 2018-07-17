package network

import (
	"fmt"
	"time"
	"bytes"
	"encoding/binary"
	"github.com/lentus/wotscoin/lib/btc"
	"github.com/lentus/wotscoin/lib/chain"
	"github.com/lentus/wotscoin/client/common"
)

const (
	PH_STATUS_NEW = 1
	PH_STATUS_FRESH = 2
	PH_STATUS_OLD = 3
	PH_STATUS_ERROR = 4
	PH_STATUS_FATAL = 5
)


func (c *OneConnection) ProcessNewHeader(hdr []byte) (int, *OneBlockToGet) {
	var ok bool
	var b2g *OneBlockToGet
	bl, _ := btc.NewBlock(hdr)

	c.Mutex.Lock()
	c.InvStore(MSG_BLOCK, bl.Hash.Hash[:])
	c.Mutex.Unlock()

	if _, ok = ReceivedBlocks[bl.Hash.BIdx()]; ok {
		common.CountSafe("HeaderOld")
		//fmt.Println("", i, bl.Hash.String(), "-already received")
		return PH_STATUS_OLD, nil
	}

	if b2g, ok = BlocksToGet[bl.Hash.BIdx()]; ok {
		common.CountSafe("HeaderFresh")
		//fmt.Println(c.PeerAddr.Ip(), "block", bl.Hash.String(), " not new but get it")
		return PH_STATUS_FRESH, b2g
	}

	common.CountSafe("HeaderNew")
	//fmt.Println("", i, bl.Hash.String(), " - NEW!")

	common.BlockChain.BlockIndexAccess.Lock()
	defer common.BlockChain.BlockIndexAccess.Unlock()

	if er, dos, _ := common.BlockChain.PreCheckBlock(bl); er != nil {
		common.CountSafe("PreCheckBlockFail")
		//println("PreCheckBlock err", dos, er.Error())
		if dos {
			return PH_STATUS_FATAL, nil
		} else {
			return PH_STATUS_ERROR, nil
		}
	}

	node := common.BlockChain.AcceptHeader(bl)
	b2g = &OneBlockToGet{Started:c.LastMsgTime, Block:bl, BlockTreeNode:node, InProgress:0}
	AddB2G(b2g)
	LastCommitedHeader = node

	if common.LastTrustedBlockMatch(node.BlockHash) {
		common.SetUint32(&common.LastTrustedBlockHeight, node.Height)
		for node != nil {
			node.Trusted = true
			node = node.Parent
		}
	}
	b2g.Block.Trusted = b2g.BlockTreeNode.Trusted

	return PH_STATUS_NEW, b2g
}


func (c *OneConnection) HandleHeaders(pl []byte) (new_headers_got int) {
	var highest_block_found uint32

	c.MutexSetBool(&c.X.GetHeadersInProgress, false)

	b := bytes.NewReader(pl)
	cnt, e := btc.ReadVLen(b)
	if e != nil {
		println("HandleHeaders:", e.Error(), c.PeerAddr.Ip())
		return
	}

	if cnt>0 {
		MutexRcv.Lock()
		defer MutexRcv.Unlock()

		for i:=0; i<int(cnt); i++ {
			var hdr [81]byte

			n, _ := b.Read(hdr[:])
			if n!=81 {
				println("HandleHeaders: pl too short", c.PeerAddr.Ip())
				c.DoS("HdrErr1")
				return
			}

			if hdr[80]!=0 {
				fmt.Println("Unexpected value of txn_count from", c.PeerAddr.Ip())
				c.DoS("HdrErr2")
				return
			}

			sta, b2g := c.ProcessNewHeader(hdr[:])
			if b2g==nil {
				if sta==PH_STATUS_FATAL {
					//println("c.DoS(BadHeader)")
					c.DoS("BadHeader")
					return
				} else if sta==PH_STATUS_ERROR {
					//println("c.Misbehave(BadHeader)")
					c.Misbehave("BadHeader", 50) // do it 20 times and you are banned
				}
			} else {
				if sta==PH_STATUS_NEW {
					if cnt==1 {
						b2g.SendInvs = true
					}
					new_headers_got++
				}
				if b2g.Block.Height > highest_block_found {
					highest_block_found = b2g.Block.Height
				}
				if c.Node.Height < b2g.Block.Height {
					c.Mutex.Lock()
					c.Node.Height = b2g.Block.Height
					c.Mutex.Unlock()
				}
				c.MutexSetBool(&c.X.GetBlocksDataNow, true)
				if b2g.TmPreproc.IsZero() { // do not overwrite TmPreproc (in case of PH_STATUS_FRESH)
					b2g.TmPreproc = time.Now()
				}
			}
		}
	}

	c.Mutex.Lock()
	c.X.LastHeadersEmpty = highest_block_found <= c.X.LastHeadersHeightAsk
	c.X.TotalNewHeadersCount += new_headers_got
	if new_headers_got==0 {
		c.X.AllHeadersReceived = true
	}
	c.Mutex.Unlock()

	return
}


func (c *OneConnection) ReceiveHeadersNow() {
	c.Mutex.Lock()
	c.X.AllHeadersReceived = false
	c.Mutex.Unlock()
}


// Handle getheaders protocol command
// https://en.bitcoin.it/wiki/Protocol_specification#getheaders
func (c *OneConnection) GetHeaders(pl []byte) {
	h2get, hashstop, e := parseLocatorsPayload(pl)
	if e != nil || hashstop==nil {
		println("GetHeaders: error parsing payload from", c.PeerAddr.Ip())
		c.DoS("BadGetHdrs")
		return
	}

	var best_block, last_block *chain.BlockTreeNode

	//common.Last.Mutex.Lock()
	MutexRcv.Lock()
	last_block = LastCommitedHeader
	MutexRcv.Unlock()
	//common.Last.Mutex.Unlock()

	common.BlockChain.BlockIndexAccess.Lock()

	//println("GetHeaders", len(h2get), hashstop.String())
	if len(h2get) > 0 {
		for i := range h2get {
			if bl, ok := common.BlockChain.BlockIndex[h2get[i].BIdx()]; ok {
				if best_block==nil || bl.Height > best_block.Height {
					//println(" ... bbl", i, bl.Height, bl.BlockHash.String())
					best_block = bl
				}
			}
		}
	} else {
		best_block = common.BlockChain.BlockIndex[hashstop.BIdx()]
	}

	if best_block==nil {
		common.CountSafe("GetHeadersBadBlock")
		best_block = common.BlockChain.BlockTreeRoot
	}

	var resp []byte
	var cnt uint32

	defer func() {
		// If we get a hash of an old orphaned blocks, FindPathTo() will panic, so...
		if r := recover(); r != nil {
			common.CountSafe("GetHeadersOrphBlk")
		}

		common.BlockChain.BlockIndexAccess.Unlock()

		// send the response
		out := new(bytes.Buffer)
		btc.WriteVlen(out, uint64(cnt))
		out.Write(resp)
		c.SendRawMsg("headers", out.Bytes())
	}()

	for cnt<2000 {
		if last_block.Height <= best_block.Height {
			break
		}
		best_block = best_block.FindPathTo(last_block)
		if best_block==nil {
			break
		}
		resp = append(resp, append(best_block.BlockHeader[:], 0)...) // 81st byte is always zero
		cnt++
	}

	// Note: the deferred function will be called before exiting

	return
}

func (c *OneConnection) sendGetHeaders() {
	MutexRcv.Lock()
	lb := LastCommitedHeader
	MutexRcv.Unlock()
	min_height := int(lb.Height) - chain.MovingCheckopintDepth
	if min_height<0 {
		min_height = 0
	}

	blks := new(bytes.Buffer)
	var cnt uint64
	var step int
	step = 1
	for cnt<50/*it shoudl never get that far, but just in case...*/ {
		blks.Write(lb.BlockHash.Hash[:])
		cnt++
		//println(" geth", cnt, "height", lb.Height, lb.BlockHash.String())
		if int(lb.Height) <= min_height {
			break
		}
		for tmp:=0; tmp<step && lb!=nil && int(lb.Height)>min_height; tmp++ {
			lb = lb.Parent
		}
		if lb==nil {
			break
		}
		if cnt>=10 {
			step = step*2
		}
	}
	var null_stop [32]byte
	blks.Write(null_stop[:])

	bhdr := new(bytes.Buffer)
	binary.Write(bhdr, binary.LittleEndian, common.Version)
	btc.WriteVlen(bhdr, cnt)

	c.SendRawMsg("getheaders", append(bhdr.Bytes(), blks.Bytes()...))
	c.X.LastHeadersHeightAsk = lb.Height
	c.MutexSetBool(&c.X.GetHeadersInProgress, true)
	c.X.GetHeadersTimeout = time.Now().Add(GetHeadersTimeout)
}
