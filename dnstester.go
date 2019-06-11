package main

import (
	"net"
	"fmt"
	"flag"
	"strings"
	"github.com/miekg/dns"
	"encoding/xml"
	"strconv"
)

type result struct {
	Channel string `xml:"channel"`
	Value string `xml:"value"`
	Lookup string `xml:"ValueLookup"`
}

type prtgbody struct {
	XMLName xml.Name `xml:"prtg"`
	TextField string `xml:"text"`
	Res []result `xml:"result"`
}

type DNScheck struct {
	DNSServer net.IP
	Hostdata map[string]hostresolv
	EHostdata map[string]hostresolv
}

type hostresolv struct {
	IPs []net.IP
	ExpectedIP net.IP
	Errstring string
	ContainExpectedIp bool
}
var (
	dnssrvs = flag.String("d", "", "DNS servers separated by comma")
	insideuri = flag.String("iu", "", "URI of the inside hosts, separated by commas. Format: URI:IP. For example pcone.mydomain.local:192.168.30.2,pctwo.mydomain.local:192.168.30.3")
	outsideuri = flag.String("ou", "", "URI of the outside hosts, separated by commas. Format: URI:IP. For example pcone.mydomain.local:192.168.30.2,pctwo.mydomain.local:192.168.30.3")
)

func FillDNSMap(result *DNScheck,urllist []string,exturi bool){
		for _,ciuri := range urllist{
			var IPs []net.IP
			Errstring := ""
			uriip := strings.Split(ciuri,":")
			client := new(dns.Client)
			message := new(dns.Msg)
			message.SetQuestion(dns.Fqdn(uriip[0]),dns.TypeA)
			eflag := false
			r,_,err := client.Exchange(message,net.JoinHostPort(result.DNSServer.String(),"53"))
			if err != nil{
				Errstring = fmt.Sprint(err)
			}else {
				if len(r.Answer) > 0 {

					for _, rrow := range r.Answer {
						onestring := rrow.String()
						strings.Fields(onestring)
						spltabonestri := strings.Split(onestring, "\t")
						IPs = append(IPs, net.ParseIP(spltabonestri[len(spltabonestri)-1]))
					}
				}

				for _, CIp := range IPs {
					if CIp.String() == net.ParseIP(uriip[1]).String() {
						eflag = true
					}
				}
			}

			if exturi{
				result.EHostdata[uriip[0]]= hostresolv{IPs:IPs,ExpectedIP:net.ParseIP(uriip[1]),Errstring:Errstring,ContainExpectedIp:eflag}
			}else {
				result.Hostdata[uriip[0]]= hostresolv{IPs:IPs,ExpectedIP:net.ParseIP(uriip[1]),Errstring:Errstring,ContainExpectedIp:eflag}
			}
		}
}

func main() {
	flag.Parse()
	var dnscheckst []DNScheck
	dnssrvslist := strings.Split(*dnssrvs,",")

	iurilist := strings.Split(*insideuri,",")
	ourilist := strings.Split(*outsideuri,",")

	for _,dnssrv := range dnssrvslist{
		dnscheckst = append(dnscheckst,DNScheck{DNSServer:net.ParseIP(dnssrv)})
		dnscheckst[len(dnscheckst)-1].Hostdata = make(map[string]hostresolv,0)
		dnscheckst[len(dnscheckst)-1].EHostdata = make(map[string]hostresolv,0)
		FillDNSMap(&dnscheckst[len(dnscheckst)-1],iurilist,false)
		FillDNSMap(&dnscheckst[len(dnscheckst)-1],ourilist,true)

	}
	var rd1 []result
	val := 4
	lval := 4
	gval := 4
	for _,ores := range dnscheckst{
		if len(ores.Hostdata) > 0{

			for _,orec := range ores.Hostdata{
				if orec.Errstring != ""{
					lval = 4
				}else {

					if orec.ContainExpectedIp == true{
						lval = 1
					}else {
						lval = 2
					}
				}
			}
		}
		if len(ores.EHostdata) > 0{
			for _,orec2 := range ores.EHostdata{
				if orec2.Errstring != ""{
					gval = 4
				}else {

					if orec2.ContainExpectedIp == true {
						gval = 1
					}else {
						gval = 3
					}
				}
			}
		}
		switch lval {
		case 1:val = gval;break
		case 2:if gval == 1 {val = lval}else {if gval == 3{val = 5}else{val = gval}};break
		default:
			break
		}
		rd1 = append(rd1,result{Channel:ores.DNSServer.String(),Value:strconv.Itoa(val),Lookup:"dnslookup"})
	}
	mt1 := &prtgbody{TextField:"",Res: rd1}
	bolB, _ := xml.Marshal(mt1)
	fmt.Println(string(bolB))
}
