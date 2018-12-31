package socketproxy

import (
	"fmt"
	"testing"
	"time"

	"local-git.dcn.ovh/dclain/dcn-gokit/kitlog"
)

// lancer avec go test -v pour afficher les logs
func TestExternalIP(t *testing.T) {
	kitlog.LogLevel = kitlog.INFO
	vIP, err := externalIP()
	if err != nil {
		fmt.Println("Error: ", err)
		t.FailNow()
	}

	fmt.Println(vIP.String())
}

func TestPingUtil(t *testing.T) {
	kitlog.LogLevel = kitlog.INFO
	vPacket := PingUtil(time.Second*2, false, false, "www.google.fr")

	if vPacket.Err != nil {
		t.Log("Erreur : ", vPacket.Err)
		t.FailNow()
	}

	if vPacket.Err == nil {
		fmt.Println((*(vPacket.IPAddrTo)).String())
		fmt.Println((*(vPacket.IPReplyTo)).String())
		fmt.Println((*(vPacket.IPSupposedSource)).String())
		fmt.Println(vPacket.PacketID)
		fmt.Println((*(vPacket.IPReplyTo)).String())
		fmt.Println((*(vPacket.IPReplyTo)).String())
		fmt.Println(vPacket.Time)
	}
}
func TestPingUtil_Case_DoublePing(t *testing.T) {
	kitlog.LogLevel = kitlog.INFO
	vPacket1 := PingUtil(time.Second*3, false, false, "www.bloop.org")
	vPacket2 := PingUtil(time.Second*1, false, false, "www.google.fr")

	if vPacket1.Err != nil {
		t.Log(">Erreur : ", vPacket1.Err)
		t.FailNow()
	}

	if vPacket1.Err == nil {
		fmt.Println(">TO", (*(vPacket1.IPAddrTo)).String())
		fmt.Println(">REPLY", (*(vPacket1.IPReplyTo)).String())
		fmt.Println(">SOURCE", (*(vPacket1.IPSupposedSource)).String())
		fmt.Println(">PacketID", vPacket1.PacketID)
		fmt.Println(">Time", vPacket1.Time)
		fmt.Println(">Timeout", vPacket1.Timeout)
	}

	if vPacket2.Err != nil {
		t.Log(">Erreur : ", vPacket2.Err)
		t.FailNow()
	}

	if vPacket2.Err == nil {
		fmt.Println(">TO", (*(vPacket2.IPAddrTo)).String())
		fmt.Println(">REPLY", (*(vPacket2.IPReplyTo)).String())
		fmt.Println(">SOURCE", (*(vPacket2.IPSupposedSource)).String())
		fmt.Println(">PacketID", vPacket2.PacketID)
		fmt.Println(">Time", vPacket2.Time)
		fmt.Println(">Timeout", vPacket2.Timeout)
	}

	//time.Sleep(time.Second * 4)
}
