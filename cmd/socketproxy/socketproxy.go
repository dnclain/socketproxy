package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"local-git.dcn.ovh/socketproxy"
)

var usage = `-ip to define an ip`

/*func main() {
	//	http.HandleFunc("/ping", controllerPing)
	//	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))

	ip := flag.String("ip", "", "an ip")
	flag.Usage = func() {
		fmt.Println(usage)
		os.Exit(-1)
	}

	privileged := flag.Bool("privileged", false, "if ping is privileged or not")

	flag.Parse()

	if *ip == "" {
		flag.Usage()
	}

	timeout, err := time.ParseDuration("1s")
	if err != nil {
		log.Fatal(err)
	}

	packet := socketproxy.PingUtil(timeout, *privileged, *ip)
	if packet != nil {
		fmt.Println("OK", packet.IPAddr.IP.String())
	} else {
		log.Fatal("sorry")
	}

}*/

func startHTTPServer() *http.Server {
	srv := &http.Server{Addr: "localhost:8080"}

	http.HandleFunc("/ping", controllerPing)

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("Httpserver: ListenAndServe() error: %s", err)
		}
	}()

	return srv
}

func main() {
	srv := startHTTPServer()

	cout := make(chan os.Signal, 1)
	signal.Notify(cout, os.Interrupt)
	signal.Notify(cout, syscall.SIGTERM)

	loop := true
	for loop {
		select {
		case <-cout:
			{
				if err := srv.Shutdown(nil); err != nil {
					panic(err) // failure/timeout shutting down the server gracefully
				} else {
					loop = false
				}
			}
		default:
			{
				// do nothing
			}
		}
	}
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

	packet := socketproxy.PingUtil(timeout, false, req.Form.Get("ip"))
	if packet == nil {
		fmt.Fprintf(w, "KO")
	} else {
		fmt.Fprintf(w, "OK:%v", packet.IPAddr.IP.String())
		log.Println(">", packet.IPAddr.IP.String())
	}
}
