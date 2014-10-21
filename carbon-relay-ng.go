// carbon-relay-ng
// route traffic to anything that speaks the Graphite Carbon protocol,
// such as Graphite's carbon-cache.py, influxdb, ...
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/Dieterbe/statsd-go"
	"github.com/graphite-ng/carbon-relay-ng/admin"
	"github.com/graphite-ng/carbon-relay-ng/routing"
	pickle "github.com/kisielk/og-rek"
	"github.com/rcrowley/goagain"
	"io"
	"log"
	"net"
	"os"
	"reflect"
	"runtime/pprof"
	"strings"
)

type StatsdConfig struct {
	Enabled  bool
	Instance string
	Host     string
	Port     int
}

type Blacklist struct {
	Patt    string
	Comment string
}

type Rec struct {
	name  string
	value string
	date  int64
}

type Config struct {
	Listen_addr        string
	Listen_addr_pickle string
	Admin_addr         string
	Http_addr          string
	Spool_dir          string
	First_only         bool
	Routes             map[string]*routing.Route
	Statsd             StatsdConfig
	Blacklist          []Blacklist
}

var (
	config_file  string
	config       Config
	to_dispatch  = make(chan []byte)
	routes       *routing.Routes
	statsdClient statsd.Client
	cpuprofile   = flag.String("cpuprofile", "", "write cpu profile to file")
)

func init() {
	log.SetFlags(log.Ltime | log.Lmicroseconds | log.Lshortfile)
}

func accept(l *net.TCPListener, config Config) {
	for {
		c, err := l.AcceptTCP()
		if nil != err {
			log.Println(err)
			break
		}
		go handle(c, config)
	}
}
func extract(in interface{}, rec *Rec, deep uint8) {
	switch reflect.TypeOf(in).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(in)
		for i := 0; i < s.Len(); i++ {
			vv := s.Index(i).Interface()
			switch vv.(type) {
			case string:
				if deep == 0 {
					rec.name = vv.(string)
					if strings.HasPrefix(rec.name, ".") {
						rec.name = rec.name[1:]
					}
				} else {
					rec.value = vv.(string)
				}
			case int64:
				rec.date = vv.(int64)
			default:
				deep += 1
				extract(vv, rec, deep)
			}

		}
	}

}
func accept_pickle(l *net.TCPListener, config Config) {
	for {
		c, err := l.AcceptTCP()
		if nil != err {
			log.Println(err)
			break
		}
		go handle_pickle(c, config)
	}
}

func handle_pickle(c *net.TCPConn, config Config) {
	defer c.Close()

	header := make([]byte, 4)
	rec := Rec{}
	for {
		_, err := io.ReadFull(c, header)
		if err != nil {
			break
		}

		size := binary.BigEndian.Uint32(header)
		data := make([]byte, size)
		_, err = io.ReadFull(c, data)
		if err != nil {
			break
		}

		iobuffer := bytes.NewReader(data)
		dec := pickle.NewDecoder(iobuffer)
		v, err := dec.Decode()
		if err != nil {
			break
		}
		s := reflect.ValueOf(v)
		for i := 0; i < s.Len(); i++ {
			extract(s.Index(i).Interface(), &rec, 0)
			to_dispatch <- []byte(fmt.Sprintf("%s %s %v\n", rec.name, rec.value, rec.date))
		}
	}
}

func handle(c *net.TCPConn, config Config) {
	defer c.Close()
	// TODO c.SetTimeout(60e9)
	r := bufio.NewReaderSize(c, 4096)
LineReader:
	for {
		buf, isPrefix, err := r.ReadLine()
		if nil != err {
			if io.EOF != err {
				log.Println(err)
			}
			break
		}
		log.Println(string(buf))
		if isPrefix { // TODO Recover from partial reads.
			log.Println("isPrefix: true")
			break
		}
		for _, blacklist := range config.Blacklist {
			if strings.Contains(string(buf), blacklist.Patt) {
				statsdClient.Increment("target_type=count.unit=Metric.direction=blacklist")
				continue LineReader
			}
		}

		buf = append(buf, '\n')
		buf_copy := make([]byte, len(buf), len(buf))
		copy(buf_copy, buf)
		statsdClient.Increment("target_type=count.unit=Metric.direction=in")
		to_dispatch <- buf_copy
	}
}

func Router() {
	for buf := range to_dispatch {
		routed := routes.Dispatch(buf, config.First_only)
		if !routed {
			log.Printf("unrouteable: %s\n", buf)
		}
	}
}

func tcpListHandler(req admin.Req) (err error) {
	if len(req.Command) != 2 {
		return errors.New("extraneous arguments")
	}
	longest_key := 9
	longest_patt := 9
	longest_addr := 9
	list := routes.List()
	for key, route := range list {
		if len(key) > longest_key {
			longest_key = len(key)
		}
		if len(route.Patt) > longest_patt {
			longest_patt = len(route.Patt)
		}
		if len(route.Addr) > longest_addr {
			longest_addr = len(route.Addr)
		}
	}
	fmt_str := fmt.Sprintf("%%%ds %%%ds %%%ds %%8v\n", longest_key+1, longest_patt+1, longest_addr+1)
	(*req.Conn).Write([]byte(fmt.Sprintf(fmt_str, "key", "pattern", "addr", "spool")))
	for key, route := range list {
		(*req.Conn).Write([]byte(fmt.Sprintf(fmt_str, key, route.Patt, route.Addr, route.Spool)))
	}
	(*req.Conn).Write([]byte("--\n"))
	return
}
func tcpAddHandler(req admin.Req) (err error) {
	key := req.Command[2]
	var patt, addr, spool_str string
	if len(req.Command) == 5 {
		patt = ""
		addr = req.Command[3]
		spool_str = req.Command[4]
	} else if len(req.Command) == 6 {
		patt = req.Command[3]
		addr = req.Command[4]
		spool_str = req.Command[5]
	} else {
		return errors.New("bad number of arguments")
	}

	spool := false
	if spool_str == "1" {
		spool = true
	}
	pickle := false

	err = routes.Add(key, patt, addr, spool, pickle, &statsdClient)
	if err != nil {
		return err
	}
	(*req.Conn).Write([]byte("added\n"))
	return
}

func tcpDelHandler(req admin.Req) (err error) {
	if len(req.Command) != 3 {
		return errors.New("bad number of arguments")
	}
	key := req.Command[2]
	err = routes.Del(key)
	if err != nil {
		return err
	}
	(*req.Conn).Write([]byte("deleted\n"))
	return
}

func tcpPattHandler(req admin.Req) (err error) {
	key := req.Command[2]
	var patt string
	if len(req.Command) == 4 {
		patt = req.Command[3]
	} else if len(req.Command) == 3 {
		patt = ""
	} else {
		return errors.New("bad number of arguments")
	}
	err = routes.Update(key, nil, &patt)
	if err != nil {
		return err
	}
	(*req.Conn).Write([]byte("updated\n"))
	return
}

func tcpHelpHandler(req admin.Req) (err error) {
	writeHelp(*req.Conn, []byte(""))
	return
}
func tcpDefaultHandler(req admin.Req) (err error) {
	writeHelp(*req.Conn, []byte("unknown command\n"))
	return
}

func writeHelp(conn net.Conn, write_first []byte) { // bytes.Buffer
	//write_first.WriteTo(conn)
	conn.Write(write_first)
	help := `
commands:
    help                                     show this menu
    route list                               list routes
    route add <key> [pattern] <addr> <spool> add the route. (empty pattern allows all). (spool has to be 1 or 0)
    route del <key>                          delete the matching route
    route patt <key> [pattern]               update pattern for given route key.  (empty pattern allows all)

`
	conn.Write([]byte(help))
}

func adminListener() {
	admin.HandleFunc("route list", tcpListHandler)
	admin.HandleFunc("route add", tcpAddHandler)
	admin.HandleFunc("route del", tcpDelHandler)
	admin.HandleFunc("route patt", tcpPattHandler)
	admin.HandleFunc("help", tcpHelpHandler)
	admin.HandleFunc("", tcpDefaultHandler)
	log.Printf("admin TCP listener starting on %v", config.Admin_addr)
	err := admin.ListenAndServe(config.Admin_addr)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(
		os.Stderr,
		"Usage: carbon-relay-ng <path-to-config>",
	)
	flag.PrintDefaults()
}

func main() {

	flag.Usage = usage
	flag.Parse()

	config_file = "/etc/carbon-relay-ng.ini"
	if 1 == flag.NArg() {
		config_file = flag.Arg(0)
	}

	if _, err := toml.DecodeFile(config_file, &config); err != nil {
		fmt.Printf("Cannot use config file '%s':\n", config_file)
		fmt.Println(err)
		return
	}
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	log.Println("initializing routes...")
	var err error
	routes, err = routing.NewRoutes(config.Routes, config.Spool_dir, &statsdClient)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	err = routes.Run()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	statsdPrefix := fmt.Sprintf("service=carbon-relay-ng.instance=%s.", config.Statsd.Instance)
	statsdClient = *statsd.NewClient(config.Statsd.Enabled, config.Statsd.Host, config.Statsd.Port, statsdPrefix)

	// Follow the goagain protocol, <https://github.com/rcrowley/goagain>.
	l, ppid, err := goagain.GetEnvs()
	lp, ppid, err := goagain.GetEnvs()
	if nil != err {
		laddr, err := net.ResolveTCPAddr("tcp", config.Listen_addr)
		lpaddr, err := net.ResolveTCPAddr("tcp", config.Listen_addr_pickle)
		if nil != err {
			log.Println(err)
			os.Exit(1)
		}
		l, err = net.ListenTCP("tcp", laddr)
		if nil != err {
			log.Println(err)
			os.Exit(1)
		}
		log.Printf("listening on %v", laddr)
		go accept(l.(*net.TCPListener), config)

		lp, err = net.ListenTCP("tcp", lpaddr)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		log.Printf("Listening pickle on %v", lpaddr)
		go accept_pickle(lp.(*net.TCPListener), config)
	} else {
		log.Printf("resuming listening on %v", l.Addr())
		go accept(l.(*net.TCPListener), config)
		go accept_pickle(lp.(*net.TCPListener), config)

		if err := goagain.KillParent(ppid); nil != err {
			log.Println(err)
			os.Exit(1)
		}
	}

	if config.Admin_addr != "" {
		go adminListener()
	}

	if config.Http_addr != "" {
		go admin.HttpListener(config.Http_addr, routes, &statsdClient)
	}

	go Router()

	if err := goagain.AwaitSignals(l); nil != err {
		log.Println(err)
		os.Exit(1)
	}
}
