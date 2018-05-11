package main

// Go code 1.9

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"local-git.dcn.ovh/dclain/socketproxy"
)

func startHTTPServer(host string, port int) *http.Server {
	srv := &http.Server{Addr: host + ":" + strconv.Itoa(port)}

	http.HandleFunc("/ping", controllerPing)

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Httpserver: ListenAndServe() error: %s", err)
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

func init() {
	flag.Usage = func() {
		fmt.Println(usage)
		os.Exit(-1)
	}
}

func main() {
	host := flag.String("h", "localhost", "the host")
	port := flag.Int("p", 9797, "the port")
	priv := flag.Bool("privileged", false, "if ping is privileged or not")

	flag.Parse()

	if *host == "" || *port <= 1024 {
		flag.Usage()
	}

	privileged = *priv

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
	Result  bool   `json:"result"`
	IP      string `json:"ip"`
	Time    string `json:"time"`
	Timeout bool   `json:"timeout"`
	Error   string `json:"error"`
}

// Ping handler control
func controllerPing(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		fmt.Fprintf(w, "ERR:%v", err)
		return
	}

	timeout, err := time.ParseDuration(req.Form.Get("timeout"))
	if err != nil {
		fmt.Fprintf(w, "ERR:%v", err)
		return
	}

	// here is the ping
	packet := socketproxy.PingUtil(timeout, false, privileged, req.Form.Get("ip"))

	// sends jsons objet by default
	result := &pingResult{Result: false, IP: req.Form.Get("ip"), Time: "-1", Timeout: false, Error: "No packet"}
	if packet != nil {
		result.Error = ""
		if packet.Err != nil {
			result.Error = packet.Err.Error()
		}
		if packet.IPAddrTo != nil {
			result.IP = packet.IPAddrTo.IP.String()
		}
		result.Timeout = packet.Timeout
		result.Time = packet.Time.String()
		result.Result = !packet.Timeout && packet.Err == nil
		socketproxy.LogInfo(packet)
	}

	json, err := json.Marshal(result)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "KO:%q", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "%s", json)
}
