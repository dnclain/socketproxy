package socketproxy

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// PingUtil can ping any host
func PingUtil(pTimeout time.Duration, pPrivileged bool, pHost string) *Packet {
	log.Println("PingUtil")
	pingertool, err := newPinger(pHost)
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
		return nil
	}

	pingertool.Timeout = pTimeout
	pingertool.SetPrivileged(pPrivileged)

	return pingertool.run()
}

/******************
	ORIGINAL CODE
 ******************/

const (
	timeSliceLength  = 8
	protocolICMP     = 1
	protocolIPv6ICMP = 58
)

var (
	ipv4Proto = map[string]string{"ip": "ip4:icmp", "udp": "udp4"}
	ipv6Proto = map[string]string{"ip": "ip6:ipv6-icmp", "udp": "udp6"}
)

// NewPinger returns a new pinger struct pointer
func newPinger(addr string) (*pinger, error) {
	ipaddr, err := net.ResolveIPAddr("ip", addr)
	if err != nil {
		return nil, err
	}

	log.Println("addr:", addr)

	var ipv4 bool
	if isIPv4(ipaddr.IP) {
		ipv4 = true
	} else if isIPv6(ipaddr.IP) {
		ipv4 = false
	}
	log.Println("ipv4:", ipv4)

	return &pinger{
		ipaddr:  ipaddr,
		addr:    addr,
		Timeout: time.Second * 1,

		network: "udp",
		ipv4:    ipv4,
		size:    timeSliceLength,
	}, nil
}

// pinger represents ICMP packet sender/receiver
type pinger struct {
	// Timeout specifies a timeout before ping exits, regardless of how many
	// packets have been received.
	Timeout time.Duration

	// Debug runs in debug mode
	Debug bool

	// Number of packets sent
	PacketsSent int

	// Number of packets received
	PacketsRecv int

	// rtts is all of the Rtts
	rtts []time.Duration

	ipaddr *net.IPAddr
	addr   string

	ipv4     bool
	source   string
	size     int
	sequence int
	network  string
}

type packet struct {
	bytes  []byte
	nbytes int
}

// Packet represents a received and processed ICMP echo packet.
type Packet struct {
	// Rtt is the round-trip time it took to ping.
	Rtt time.Duration

	// IPAddr is the address of the host being pinged.
	IPAddr *net.IPAddr

	// NBytes is the number of bytes in the message.
	Nbytes int

	// Seq is the ICMP sequence number.
	Seq int
}

// Addr returns the string ip address of the target host.
func (p *pinger) Addr() string {
	return p.addr
}

// SetPrivileged sets the type of ping pinger will send.
// false means pinger will send an "unprivileged" UDP ping.
// true means pinger will send a "privileged" raw ICMP ping.
// NOTE: setting to true requires that it be run with super-user privileges.
func (p *pinger) SetPrivileged(privileged bool) {
	if privileged {
		p.network = "ip"
	} else {
		p.network = "udp"
	}
}

// Privileged returns whether pinger is running in privileged mode.
func (p *pinger) Privileged() bool {
	return p.network == "ip"
}

func (p *pinger) run() *Packet {
	var conn *icmp.PacketConn
	if p.ipv4 {
		if conn = p.listen(ipv4Proto[p.network], p.source); conn == nil {
			return nil
		}
	} else {
		if conn = p.listen(ipv6Proto[p.network], p.source); conn == nil {
			return nil
		}
	}
	// close sera appelé à la fin de la fonction.
	defer conn.Close()

	// unbuffered channel
	recv := make(chan *rPacket)
	// start the go routine (try to listen for return packet first)
	go p.recvICMP(p.Timeout, conn, recv)
	// then send a packet
	err := p.sendICMP(conn)
	if err != nil {
		fmt.Println(err.Error())
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)

	var result *Packet
	goOn := true
	for goOn {
		select {
		case <-c:
			goOn = false
		case r := <-recv:
			if r.err != nil || r.timeout {
				goOn = false
			} else {
				pkt, err := p.processPacket(r.packet)
				if err != nil {
					fmt.Println("FATAL: ", err.Error())
				}
				result = pkt
				goOn = false
			}
		}
	}

	close(recv)
	return result
}

type rPacket struct {
	packet  *packet
	time    time.Duration
	timeout bool
	err     error
}

/**
 * Wait for an ICMP packet. Return the time.
 */
func (p *pinger) recvICMP(timeout time.Duration, conn *icmp.PacketConn, recv chan<- *rPacket) {
	log.Println("recieveICMP")
	start := time.Now()
	bytes := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, _, err := conn.ReadFrom(bytes)
	duration := time.Since(start)
	if err != nil {
		if neterr, ok := err.(*net.OpError); ok {
			if neterr.Timeout() {
				log.Println("not cool => timeout. ", neterr)
				recv <- &rPacket{packet: nil, time: duration, timeout: true, err: neterr}
			} else {
				log.Println("not cool => error. ", neterr)
				recv <- &rPacket{packet: &packet{bytes: bytes, nbytes: n}, time: duration, timeout: false, err: neterr}
			}
		}
	} else {
		log.Println("cool => packet to channel")
		recv <- &rPacket{packet: &packet{bytes: bytes, nbytes: n}, time: duration, timeout: false, err: nil}
	}
}

func (p *pinger) processPacket(recv *packet) (*Packet, error) {
	var bytes []byte
	var proto int
	if p.ipv4 {
		if p.network == "ip" {
			bytes = ipv4Payload(recv.bytes)
		} else {
			bytes = recv.bytes
		}
		proto = protocolICMP
	} else {
		bytes = recv.bytes
		proto = protocolIPv6ICMP
	}

	var m *icmp.Message
	var err error
	if m, err = icmp.ParseMessage(proto, bytes[:recv.nbytes]); err != nil {
		return nil, fmt.Errorf("Error parsing icmp message")
	}

	if m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply {
		// Not an echo reply, ignore it
		return nil, nil
	}

	outPkt := &Packet{
		Nbytes: recv.nbytes,
		IPAddr: p.ipaddr,
	}

	switch pkt := m.Body.(type) {
	case *icmp.Echo:
		outPkt.Rtt = time.Since(bytesToTime(pkt.Data[:timeSliceLength]))
		outPkt.Seq = pkt.Seq
		p.PacketsRecv++
	default:
		// Very bad, not sure how this can happen
		return nil, fmt.Errorf("Error, invalid ICMP echo reply. Body type: %T, %s",
			pkt, pkt)
	}

	p.rtts = append(p.rtts, outPkt.Rtt)

	return outPkt, nil
}

func (p *pinger) sendICMP(conn *icmp.PacketConn) error {
	log.Println("sendICMP")
	var typ icmp.Type
	if p.ipv4 {
		typ = ipv4.ICMPTypeEcho
	} else {
		typ = ipv6.ICMPTypeEchoRequest
	}

	var dst net.Addr = p.ipaddr
	if p.network == "udp" {
		dst = &net.UDPAddr{IP: p.ipaddr.IP, Zone: p.ipaddr.Zone}
	}

	t := timeToBytes(time.Now())
	if p.size-timeSliceLength != 0 {
		t = append(t, byteSliceOfSize(p.size-timeSliceLength)...)
	}
	bytes, err := (&icmp.Message{
		Type: typ, Code: 0,
		Body: &icmp.Echo{
			ID:   rand.Intn(65535),
			Seq:  p.sequence,
			Data: t,
		},
	}).Marshal(nil)
	if err != nil {
		return err
	}

	for {
		if _, err := conn.WriteTo(bytes, dst); err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Err == syscall.ENOBUFS {
					continue
				}
			}
		}
		p.PacketsSent++
		p.sequence++
		break
	}
	return nil
}

func (p *pinger) listen(netProto string, source string) *icmp.PacketConn {
	conn, err := icmp.ListenPacket(netProto, source)
	if err != nil {
		fmt.Printf("Error listening for ICMP packets: %s\n", err.Error())
		return nil
	}
	return conn
}

func byteSliceOfSize(n int) []byte {
	b := make([]byte, n)
	for i := 0; i < len(b); i++ {
		b[i] = 1
	}

	return b
}

func ipv4Payload(b []byte) []byte {
	if len(b) < ipv4.HeaderLen {
		return b
	}
	hdrlen := int(b[0]&0x0f) << 2
	return b[hdrlen:]
}

func bytesToTime(b []byte) time.Time {
	var nsec int64
	for i := uint8(0); i < 8; i++ {
		nsec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nsec/1000000000, nsec%1000000000)
}

func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}

func isIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len
}

func timeToBytes(t time.Time) []byte {
	nsec := t.UnixNano()
	b := make([]byte, 8)
	for i := uint8(0); i < 8; i++ {
		b[i] = byte((nsec >> ((7 - i) * 8)) & 0xff)
	}
	return b
}
