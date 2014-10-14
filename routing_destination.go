package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/Dieterbe/statsd-go"
	"github.com/graphite-ng/carbon-relay-ng/nsqd"
	pickle "github.com/kisielk/og-rek"
	"log"
	"net"
	"os"
	"regexp"
	"sync"
	"time"
)

type Destination struct {
	// basic properties in init and copy
	Key        string         // to identify in stats/logs
	Patt       string         // regex string
	Addr       string         // tcp dest
	spoolDir   string         // where to store spool files (if enabled)
	Spool      bool           // spool metrics to disk while dest down?
	Pickle     bool           // send in pickle format?
	Online     bool           // state of connection online/offline
	instrument *statsd.Client // to submit stats to

	// set automatically in init, passed on in copy
	Reg *regexp.Regexp // compiled version of patt

	// set in/via Run()
	ch           chan []byte       // to pump data to dest
	shutdown     chan bool         // signals shutdown internally
	queue        *nsqd.DiskQueue   // queue used if spooling enabled
	raddr        *net.TCPAddr      // resolved remote addr
	connUpdates  chan *net.TCPConn // when the dest changes (possibly nil)
	inConnUpdate chan bool         // to signal when we start a new conn and when we finish
}

// after creating, run Run()!
func NewDestination(key, patt, addr, spoolDir string, spool, pickle bool, instrument *statsd.Client) (*Destination, error) {
	dest := &Destination{
		Key:        key,
		Patt:       "",
		Addr:       addr,
		spoolDir:   spoolDir,
		Spool:      spool,
		instrument: instrument,
		Pickle:     pickle,
	}
	err := dest.updatePattern(patt)
	if err != nil {
		return nil, err
	}
	return dest, nil
}

// a "basic" static copy of the dest, not actually running
func (dest *Destination) Copy() *Destination {
	return &Destination{
		Key:        dest.Key,
		Patt:       dest.Patt,
		Addr:       dest.Addr,
		spoolDir:   dest.spoolDir,
		Spool:      dest.Spool,
		instrument: dest.instrument,
		Reg:        dest.Reg,
		Pickle:     dest.Pickle,
		Online:     dest.Online,
	}
}

func (dest *Destination) updatePattern(pattern string) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	dest.Patt = pattern
	dest.Reg = regex
	return nil
}

func (dest *Destination) Run() (err error) {
	dest.ch = make(chan []byte)
	dest.shutdown = make(chan bool)
	dest.connUpdates = make(chan *net.TCPConn)
	dest.inConnUpdate = make(chan bool)
	if dest.Spool {
		dqName := "spool_" + dest.Key
		dest.queue = nsqd.NewDiskQueue(dqName, dest.spoolDir, 200*1024*1024, 1000, 2*time.Second).(*nsqd.DiskQueue)
	}
	go dest.relay()
	return err
}

func (dest *Destination) Shutdown() error {
	if dest.shutdown == nil {
		return errors.New("not running yet")
	}
	dest.shutdown <- true
	return nil
}

func (dest *Destination) updateConn(addr string) error {
	log.Printf("%v (re)connecting to %v\n", dest.Key, addr)
	dest.inConnUpdate <- true
	defer func() { dest.inConnUpdate <- false }()
	raddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		log.Printf("%v resolve failed: %s\n", dest.Key, err.Error())
		return err
	}
	laddr, _ := net.ResolveTCPAddr("tcp", "0.0.0.0")
	new_conn, err := net.DialTCP("tcp", laddr, raddr)
	if err != nil {
		log.Printf("%v connect failed: %s\n", dest.Key, err.Error())
		return err
	}
	log.Printf("%v connected\n", dest.Key)
	if addr != dest.Addr {
		log.Printf("%v update address to %v (%v)\n", dest.Key, addr, raddr)
		dest.Addr = addr
		dest.raddr = raddr
	}
	dest.connUpdates <- new_conn
	return nil
}

// TODO func (l *TCPListener) SetDeadline(t time.Time)
// TODO Decide when to drop this buffer and move on.
func (dest *Destination) relay() {
	period_assure_conn := time.Duration(60) * time.Second
	ticker := time.NewTicker(period_assure_conn)
	var to_unspool chan []byte
	var conn *net.TCPConn

	process_packet := func(buf []byte) {
		if conn == nil {
			if dest.Spool {
				dest.instrument.Increment("dest=" + dest.Key + ".target_type=count.unit=Metric.direction=spool")
				dest.queue.Put(buf)
			} else {
				// note, we drop packets while we set up connection
				dest.instrument.Increment("dest=" + dest.Key + ".target_type=count.unit=Metric.direction=drop")
			}
			return
		}
		dest.instrument.Increment("dest=" + dest.Key + ".target_type=count.unit=Metric.direction=out")

		var err error
		var n int
		if dest.Pickle {
			dp, err := parseDataPoint(buf)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return // no point in spooling these again, so just drop the packet
			}
			dataBuf := &bytes.Buffer{}
			pickler := pickle.NewEncoder(dataBuf)

			// pickle format (in python talk): [(path, (timestamp, value)), ...]
			point := []interface{}{string(dp.Name), []interface{}{dp.Time, dp.Val}}
			list := []interface{}{point}
			pickler.Encode(list)
			messageBuf := &bytes.Buffer{}
			err = binary.Write(messageBuf, binary.BigEndian, uint64(dataBuf.Len()))
			if err != nil {
				log.Fatal(err.Error())
			}
			messageBuf.Write(dataBuf.Bytes())
			n, err = conn.Write(messageBuf.Bytes())
			buf = messageBuf.Bytes() // so that we can check len(buf) later
		} else {
			n, err = conn.Write(buf)
		}
		if err != nil {
			dest.instrument.Increment("dest=" + dest.Key + ".target_type=count.unit=Err")
			log.Println(err)
			conn.Close()
			conn = nil
			if dest.Spool {
				fmt.Println("writing to spool")
				dest.queue.Put(buf)
			}
			return
		}
		if len(buf) != n {
			dest.instrument.Increment("dest=" + dest.Key + ".target_type=count.unit=Err")
			log.Printf(dest.Key+" truncated: %s\n", buf)
			conn.Close()
			conn = nil
			if dest.Spool {
				fmt.Println("writing to spool")
				dest.queue.Put(buf)
			}
		}
	}

	conn_updates := 0
	go dest.updateConn(dest.Addr)

	for {
		// only process spool queue if we have an outbound connection
		if conn != nil && dest.Spool {
			to_unspool = dest.queue.ReadChan()
		} else {
			to_unspool = nil
		}

		select {
		case inConnUpdate := <-dest.inConnUpdate:
			if inConnUpdate {
				conn_updates += 1
			} else {
				conn_updates -= 1
			}
		case new_conn := <-dest.connUpdates:
			conn = new_conn // can be nil and that's ok (it means we had to [re]connect but couldn't)
			dest.Online = conn != nil
		case <-ticker.C: // periodically try to bring connection (back) up, if we have to, and no other connect is happening
			if conn == nil && conn_updates == 0 {
				go dest.updateConn(dest.Addr)
			}
		case <-dest.shutdown:
			//fmt.Println(dest.Key + " dest relay -> requested shutdown. quitting")
			return
		case buf := <-to_unspool:
			process_packet(buf)
		case buf := <-dest.ch:
			process_packet(buf)
		}
	}

}