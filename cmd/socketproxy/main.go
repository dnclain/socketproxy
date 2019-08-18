package main

// Go code 1.11

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"local-git.dcn.ovh/dclain/dcn-gokit/kitlog"
	"local-git.dcn.ovh/dclain/socketproxy"
)

// portFree checks if the TCP port is free
// if not, return a new free new one
func selectFreePort(host string, port int) int {
	vResult := port

	vNope := true
	i := 1
	for vNope && i <= 5 {
		logSP.Debug("tries : {}", i)
		ln, err := net.Listen("tcp", host+":"+strconv.Itoa(vResult))
		if err != nil {
			logSP.Warn("TCP Port {} not free with error '{}', try a new one", vResult, err)
			vResult++
		} else {
			// found free port
			logSP.Info("Found free TCP Port {}", vResult)
			vNope = false
		}
		if ln != nil {
			err = ln.Close()
			if err != nil {
				logSP.Fatal("Unable to close port with error '{}'. Weird. Stopping the process...", err)
			}
		}
		i++
	}

	if vNope {
		logSP.Fatal("Unable to find a free port, event after {} tries. Stopping the process...", i-1)
	} else {
		fmt.Printf("{\"freePort\" : %d}\n", vResult)
	}

	return vResult
}

func startHTTPServer(host string, port int) *http.Server {
	vPort := selectFreePort(host, port)

	srv := &http.Server{Addr: host + ":" + strconv.Itoa(vPort)}

	http.HandleFunc("/ping", controllerPing)

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			logSP.Fatal("Httpserver: ListenAndServe() error: {}", err)
		}
	}()

	return srv
}

var usage = `
	-h defines host instead of 'localhost'
	-p defines port superior to 1024 instead of '9797'
	-privileged activates privileged ping mode'
`
var privileged = false
var debug = false

var logSP kitlog.Log
var logUS kitlog.Log

func init() {
	fmt.Printf("-----------------------------------\n")
	fmt.Printf("Version %s\n", "1.0.1")
	fmt.Printf("-----------------------------------\n")
	flag.Usage = func() {
		fmt.Println(usage)
		os.Exit(-1)
	}
	logSP = kitlog.Logger("socketproxy")
	logUS = kitlog.CategoryLogger(kitlog.US)
}

func main() {
	host := flag.String("h", "localhost", "the host")
	port := flag.Int("p", 9797, "the port > 1024")
	priv := flag.Bool("privileged", false, "if ping is privileged or not")
	dbg := flag.Bool("debug", false, "display debug traces")

	flag.Parse()

	if *host == "" || *port <= 1024 {
		flag.Usage()
	}

	// debug mode or not
	if *dbg {
		kitlog.LogLevel = kitlog.TRACE
	} else {
		kitlog.LogLevel = kitlog.INFO
	}

	privileged = *priv
	debug = *dbg

	srv := startHTTPServer(*host, *port)

	cout := make(chan os.Signal, 1)
	signal.Notify(cout, os.Interrupt)
	signal.Notify(cout, syscall.SIGTERM)

	// attend une interruption
	// plus efficace et moins consommateur de ressource que de faire un for / select
	<-cout

	if err := srv.Shutdown(nil); err != nil {
		panic(err) // failure/timeout shutting down the server gracefully
	}
}

type pingResult struct {
	Result  bool          `json:"result"`
	IP      string        `json:"ip"`
	Time    time.Duration `json:"time"`
	Timeout bool          `json:"timeout"`
	Error   string        `json:"error"`
}

// Ping handler control
func controllerPing(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		logUS.Error("Unable to parse form : {}", err)
		fmt.Fprintf(w, "ERR:%v", err)
		return
	}
	logUS.Info("Ping with parameter {}", req.Form)

	timeout, err := time.ParseDuration(req.Form.Get("timeout"))
	if err != nil {
		logUS.Error("Unable to parse duration : {}", err)
		fmt.Fprintf(w, "ERR:%v", err)
		return
	}

	// here is the ping
	packet := socketproxy.PingUtil(timeout, debug, privileged, req.Form.Get("ip"))

	// sends jsons objet by default
	result := &pingResult{Result: false, IP: req.Form.Get("ip"), Time: 0, Timeout: false, Error: "No packet"}
	if packet != nil {
		result.Error = ""
		if packet.Err != nil {
			result.Error = packet.Err.Error()
		}
		if packet.IPAddrTo != nil {
			result.IP = packet.IPAddrTo.IP.String()
		}
		result.Timeout = packet.Timeout
		result.Time = packet.Time
		result.Result = !packet.Timeout && packet.Err == nil
		logSP.Debug("{}", packet)
	}

	json, err := json.Marshal(result)
	if err != nil {
		logUS.Error("Unable to encode result in json : {}", err)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "KO:%q", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "%s", json)
}
