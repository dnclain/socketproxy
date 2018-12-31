package socketproxy

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"local-git.dcn.ovh/dclain/dcn-gokit/kitlog"

	hashids "github.com/speps/go-hashids"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var logPU kitlog.Log
var logSCE kitlog.Log

func init() {
	logSCE = kitlog.CategoryLogger(kitlog.SRV)
	logPU = kitlog.Logger("pingutils")
}

// PingUtil can ping any host. Each echo request is independent.
func PingUtil(pTimeout time.Duration, pDebug bool, pPrivileged bool, pHostDest string) *Packet {
	logPU.Debug("Start PingUtil timeout:{} debug:{} privileged:{} host:{}", pTimeout, pDebug, pPrivileged, pHostDest)
	vPingertool, err := newPinger(pHostDest, pDebug)
	if err != nil {
		logPU.Error(fmt.Sprintf("%s", err.Error()))
		return nil
	}

	vPingertool.Timeout = pTimeout
	logPU.Debug("{}|Timeout:{}", vPingertool.ID, pTimeout)
	vPingertool.SetPrivileged(pPrivileged)
	logPU.Debug("{}|Priviledged:{}", vPingertool.ID, pPrivileged)

	return vPingertool.run()
}

/*******************************
	Independent ECHO REQUEST
 *******************************/

const (
	// reserved time byte
	cTimeSliceLength = 8
	// ICMP ipv4 protocol version
	cProtocolICMP = 1
	// ICMP ipv6 protocole version
	cProtocolIPv6ICMP = 58
)

var (
	ipv4Proto = map[string]string{"ip": "ip4:icmp", "udp": "udp4"}
	ipv6Proto = map[string]string{"ip": "ip6:ipv6-icmp", "udp": "udp6"}
)

// Packet represents a received and processed ICMP echo packet.
type Packet struct {
	// Time is the total time taken to send and recieve one packet.
	Time time.Duration

	// Timeout indicates if a timeout occurs
	Timeout bool

	// Err indicates if an error occurs during the ping process.
	Err error

	// IPSupposedSource is the address of the host that is pinging.
	IPSupposedSource *net.IP

	// IPReplyTo is the address of the host where the ping reply where recieved.
	IPReplyTo *net.Addr

	// IPAddrTo is the address of the host being pinged.
	IPAddrTo *net.IPAddr

	// NBytes is the size of the echo reply
	NBytes int

	// PacketID is a random int from 0 to 65535 ID attached with the echo packet.
	PacketID int

	// ID is a unique hashID sends into the ICMP packet
	ID string
}

// rawPacket est le contenu reçu
type rawPacket struct {
	// ipAddrHost is the address of the target of the packet (specifically, the sender of the originall ping)
	ipAddrHost *net.Addr
	bytes      []byte
	nbytes     int
}

// externalIP return the first external ipv4/ipv6 address
func externalIP() (*net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}

			return &ip, nil
			/*			ip = ip.To4()
						if ip == nil {
							continue // not an ipv4 address
						}
						return ip.String(), nil */
		}
	}
	return nil, errors.New("are you connected to the network?")
}

// newPinger returns a new pinger struct pointer
func newPinger(pAddr string, pDebug bool) (*pinger, error) {
	// target IP
	vIPAddrTo, err := net.ResolveIPAddr("ip", pAddr)
	if err != nil {
		return nil, err
	}
	logPU.Debug("Target IP resolved: {}", vIPAddrTo.String())

	// source IP (TODO : must be the main root)
	vIPFrom, err := externalIP()
	if err != nil {
		return nil, err
	}
	logPU.Debug("Source IP resolved: {}", vIPFrom.String())

	vEncodedID := "no-id"
	{
		// create a unique hashid for this pinger.
		vHashidConfig := hashids.NewData()
		vHashidConfig.Salt = "1234567890àç!è§('(§è!çà)azertyuiopmlkjhgfdsqwxcvbn,;:="
		vHashidConfig.MinLength = 10
		vHashidEncoder, _ := hashids.NewWithData(vHashidConfig)
		vEncodedID, _ = vHashidEncoder.Encode([]int{rand.Int(), rand.Int()})
		logPU.Debug("{} | Packet ID generated", vEncodedID)
	}

	// vIsIpv4 mode or not
	var vIsIpv4 bool
	if isIPv4(vIPAddrTo.IP) {
		vIsIpv4 = true
	} else if isIPv6(vIPAddrTo.IP) {
		vIsIpv4 = false
	}
	logPU.Debug("{} | Mode ipv4:{}", vEncodedID, vIsIpv4)

	return &pinger{
		ipAddrTo: vIPAddrTo,
		ipFrom:   vIPFrom,
		addr:     pAddr,
		// par défaut, une seconde
		Timeout: time.Second * 1,
		ID:      vEncodedID,
		network: "udp",
		ipv4:    vIsIpv4,
		size:    cTimeSliceLength,
	}, nil
}

// pinger represents an ICMP packet sender/receiver
type pinger struct {
	// Timeout specifies a timeout before ping exits, regardless of how many
	// packets have been received.
	Timeout time.Duration

	// Debug runs in debug mode
	Debug bool

	// ID is the unique id for this pinger.
	// This id is sent into the ICMP echo request packet to discriminate replies.
	ID string

	// ipAddrFrom is the translated source ip address.
	ipFrom *net.IP
	// ipAddrTo is the translated target ip address.
	ipAddrTo *net.IPAddr

	// addr is the original entered dest addr echo request
	addr string
	// ipv4 mode
	ipv4 bool
	// what ip must listen to incoming icmp packet
	source string
	// the size of timestamp in the packet
	size int

	network string
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

// run démarre le ping get attend la réponse.
// une configuration est au préalable nécessaire.
func (p *pinger) run() *Packet {
	// récupération d'un Listener de paquet ICMP
	var vConn *icmp.PacketConn
	if p.ipv4 {
		if vConn = p.listen(ipv4Proto[p.network], p.source); vConn == nil {
			return nil
		}
	} else {
		if vConn = p.listen(ipv6Proto[p.network], p.source); vConn == nil {
			return nil
		}
	}
	// close sera appelé à la fin de la fonction.
	defer vConn.Close()

	// unbuffered channel
	recv := make(chan *Packet)

	// process a random ID for this particular packet.
	vRandomID := rand.Intn(65535)

	// starts the go routine (try to listen for return packet first)
	go p.recvICMP(p.Timeout, vConn, vRandomID, recv)
	// then send a packet
	err := p.sendICMP(vConn, vRandomID)
	if err != nil {
		fmt.Println(err.Error())
	}

	// a mean to stop the current ping.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)

	var vResult *Packet
	vGoOn := true
	for vGoOn {
		select {
		case <-c:
			vGoOn = false
		case vResult = <-recv:
			vGoOn = false
		}
		// permet de ne pas trop consommer de ressource dans la boucle
		time.Sleep(time.Microsecond * 1)
	}

	close(recv)
	return vResult
}

/**
 * recvICMP waits for an ICMP packet and processes it. Only packets that are generated from conn are retrieved and process.
 */
func (p *pinger) recvICMP(pTimeout time.Duration, pConn *icmp.PacketConn, pRandomID int, pChanRecv chan<- *Packet) {
	vWait := time.Now()
	logSCE.Debug("{} | Waiting packet ({}) from {} since '{}'", p.ID, pRandomID, p.ipFrom.String(), vWait.Format("2006-01-02 15:04:05.000"))
	// retrieves a 512 bytes packet, the size of the packet that was generated before.
	vArReplyBuffer := make([]byte, 512)
	// recieve any packet that was generated by sendICMP function, but process only the one with double ID.
	vNRecievedPacket := 0
	for {
		// timeout if we received only packets we did'nt expect, or if other error occurs.
		vGeneralTimeout := time.Since(vWait)
		if vGeneralTimeout < pTimeout {
			pConn.SetReadDeadline(time.Now().Add(pTimeout - vGeneralTimeout))
		} else {
			logSCE.Info("{} | General Timeout. No suitable packet recieved within {}", p.ID, vGeneralTimeout)
			pChanRecv <- &Packet{Err: fmt.Errorf("General timeout. Recieved " + strconv.Itoa(vNRecievedPacket) + " packets, but not the one we expected, or other problem may occurs"), ID: p.ID, PacketID: pRandomID, Time: vGeneralTimeout, Timeout: true, IPAddrTo: p.ipAddrTo, IPSupposedSource: p.ipFrom}
			break
		}

		vBytesRed, vFrom, err := pConn.ReadFrom(vArReplyBuffer)
		vDuration := time.Since(vWait)
		if err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Timeout() {
					logSCE.Info("{} | Timeout: {}", p.ID, neterr)
					pChanRecv <- &Packet{Err: neterr, ID: p.ID, PacketID: pRandomID, Time: vDuration, Timeout: true, IPSupposedSource: p.ipFrom}
					break
				} else {
					logSCE.Error("{} | Network error: {}", p.ID, neterr)
					// make sure
					var vRawPacket = &rawPacket{bytes: vArReplyBuffer, nbytes: vBytesRed, ipAddrHost: &vFrom}
					vPacket, _ := p.processPacket(vRawPacket)
					pChanRecv <- vPacket
					break
				}
			} else {
				logSCE.Warn("{} | Unexpected Error. New attempt...: {}", p.ID, neterr)
				// not a network problem, new attempt next time
			}
		} else {
			// récupère le packet, et s'assure que c'est bien pour lui
			var rawPacket = &rawPacket{bytes: vArReplyBuffer, nbytes: vBytesRed, ipAddrHost: &vFrom}
			processedPacket, err := p.processPacket(rawPacket)
			if err != nil {
				logSCE.Error("{} | Unexpected error processing the packet: {}", p.ID, err)
				pChanRecv <- &Packet{Err: err, ID: p.ID, PacketID: pRandomID, Time: vDuration, Timeout: false, IPSupposedSource: p.ipFrom}
				break
			} else {
				if processedPacket == nil {
					logSCE.Warn("{} | Packet recieved is not an ICMP one", p.ID)
					vNRecievedPacket++
				} else {
					if processedPacket.ID == p.ID && processedPacket.PacketID == pRandomID {
						vReply := time.Now()
						logSCE.Info("{} | Reply packet ({}) recieved within {} from {} at '{}'", p.ID, strconv.Itoa(processedPacket.PacketID), processedPacket.Time, p.ipFrom.String(), vReply.Format("2006-01-02 15:04:05.000"))
						pChanRecv <- processedPacket
						break
					} else {
						logSCE.Warn("{} | Huh ? Unexpected reply recieved with ID ({}) and packet ID ({}). Expected packet ID:{}", p.ID, processedPacket.ID, strconv.Itoa(processedPacket.PacketID), pRandomID)
						vNRecievedPacket++
					}
				}
			}

		}
	}
}

func (p *pinger) processPacket(pRecv *rawPacket) (*Packet, error) {
	var vArBytesBuffer []byte
	var vProto int
	if p.ipv4 {
		if p.Privileged() {
			vArBytesBuffer = ipv4Payload(pRecv.bytes)
		} else {
			vArBytesBuffer = pRecv.bytes
		}
		vProto = cProtocolICMP
	} else {
		vArBytesBuffer = pRecv.bytes
		vProto = cProtocolIPv6ICMP
	}

	var m *icmp.Message
	var err error
	if m, err = icmp.ParseMessage(vProto, vArBytesBuffer[:pRecv.nbytes]); err != nil {
		return nil, fmt.Errorf("Error parsing icmp message : " + err.Error())
	}

	if m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply {
		// Not an echo reply, ignore it
		return nil, nil
	}

	outPkt := &Packet{
		NBytes:           pRecv.nbytes,
		IPAddrTo:         p.ipAddrTo,
		IPSupposedSource: p.ipFrom,
		IPReplyTo:        pRecv.ipAddrHost,
	}

	switch pkt := m.Body.(type) {
	case *icmp.Echo:
		outPkt.Time = time.Since(bytesToTime(pkt.Data[:cTimeSliceLength]))
		outPkt.PacketID = pkt.ID
		outPkt.ID = (string)(pkt.Data[cTimeSliceLength:])
	default:
		// Very bad, not sure how this can happen
		return nil, fmt.Errorf("Error, invalid ICMP echo reply. Body type: %T, %s",
			pkt, pkt)
	}

	return outPkt, nil
}

// sendICMP envoie un packet icmp.
func (p *pinger) sendICMP(conn *icmp.PacketConn, pRandomID int) error {
	vSendDate := time.Now()
	logSCE.Info("{} | Sending packet ({}) to {} since '{}'", p.ID, pRandomID, p.ipAddrTo.String(), vSendDate.Format("2006-01-02 15:04:05.000"))
	var typ icmp.Type
	if p.ipv4 {
		typ = ipv4.ICMPTypeEcho
	} else {
		typ = ipv6.ICMPTypeEchoRequest
	}

	var dst net.Addr = p.ipAddrTo
	if !p.Privileged() {
		dst = &net.UDPAddr{IP: p.ipAddrTo.IP, Zone: p.ipAddrTo.Zone}
	}

	t := timeToBytes(time.Now())
	if p.size-cTimeSliceLength != 0 {
		t = append(t, byteSliceOfSize(p.size-cTimeSliceLength)...)
	}
	t = append(t, []byte(p.ID)...)
	bytes, err := (&icmp.Message{
		Type: typ, Code: 0,
		Body: &icmp.Echo{
			ID:   pRandomID,
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
		break
	}

	return nil
}

func (p *pinger) listen(netProto string, source string) *icmp.PacketConn {
	conn, err := icmp.ListenPacket(netProto, source)
	if err != nil {
		logSCE.Error("{} | Error listening for ICMP packets: {}", p.ID, err.Error())
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
