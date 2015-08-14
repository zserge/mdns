package mdns

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	ipv4mcastaddr = &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.251"),
		Port: 5353,
	}
	ipv6mcastaddr = &net.UDPAddr{
		IP:   net.ParseIP("ff02::fb"),
		Port: 5353,
	}
)

// User query to resolve hostname or discover service
type query struct {
	questions []dns.Question
	results   chan dns.RR
	timeout   <-chan time.Time
}

// Incoming DNS message
type msg struct {
	*dns.Msg
	*net.UDPAddr
	*net.UDPConn
}

type MDNS interface {
	Resolve(host string) []net.IP
	Browse(service string, resolvePorts bool) []string
	Shutdown()
}

type mdns struct {
	local   map[string][]dns.RR
	connv4  *net.UDPConn
	connv6  *net.UDPConn
	queries chan *query
	pending []*query
	exit    chan bool
}

func localRR(hostname string, services map[string]int) (map[string][]dns.RR, error) {
	rrs := map[string][]dns.RR{}
	addrs, err := net.InterfaceAddrs()
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
		if ip.IsLoopback() {
			continue
		}
		if ip = ip.To4(); ip != nil {
			for _, record := range []string{
				fmt.Sprintf("%s.local. 10 IN A %s", hostname, ip.String()),
				fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa. 10 IN PTR %s.local.",
					ip[3], ip[2], ip[1], ip[0], hostname),
			} {
				if rr, err := dns.NewRR(record); err != nil {
					return nil, err
				} else {
					rrs[rr.Header().Name] = append(rrs[rr.Header().Name], rr)
				}
			}

			for s, port := range services {
				for _, record := range []string{
					fmt.Sprintf("%s.local. 60 IN PTR %s.%s.local.", s, hostname, s),
					fmt.Sprintf("%s.%s.local. 60 IN SRV 0 0 %d %s.local.",
						hostname, s, port, hostname),
					fmt.Sprintf("%s.%s.local. 60 IN TXT \"\"", hostname, s),
					fmt.Sprintf("_services._dns-sd._udp.local. 60 IN PTR %s.local.", s),
				} {
					if rr, err := dns.NewRR(record); err != nil {
						return nil, err
					} else {
						rrs[rr.Header().Name] = append(rrs[rr.Header().Name], rr)
					}
				}
			}
		}
	}
	return rrs, nil
}

func NewMDNS(hostname string, services map[string]int) (MDNS, error) {
	rrs, err := localRR(hostname, services)
	if err != nil {
		return nil, err
	}

	connv4, err := net.ListenMulticastUDP("udp4", nil, ipv4mcastaddr)
	if err != nil {
		return nil, err
	}

	connv6, err := net.ListenMulticastUDP("udp6", nil, ipv6mcastaddr)
	if err != nil {
		connv6 = nil
	}

	m := &mdns{
		local:   rrs,
		connv4:  connv4,
		connv6:  connv6,
		pending: []*query{},
		queries: make(chan *query, 64),
		exit:    make(chan bool, 0),
	}

	qst := make(chan msg, 0)
	go m.loop(qst)
	go m.readloop(connv4, qst)
	go m.readloop(connv6, qst)

	return m, nil
}

// Get IP addresses related to the given local hostname
func (m *mdns) Resolve(host string) []net.IP {
	results := make(chan dns.RR)
	m.queries <- &query{
		questions: []dns.Question{
			dns.Question{dns.Fqdn(host), dns.TypeA, dns.ClassINET},
			dns.Question{dns.Fqdn(host), dns.TypeAAAA, dns.ClassINET},
		},
		results: results,
	}
	ipset := map[string]net.IP{}
	ips := []net.IP{}
	for rr := range results {
		var ip net.IP
		switch rr := rr.(type) {
		case *dns.A:
			ip = rr.A
		case *dns.AAAA:
			ip = make([]byte, 16)
			copy(ip, rr.AAAA[:])
		default:
			continue
		}
		if _, ok := ipset[ip.String()]; !ok {
			ipset[ip.String()] = ip
			ips = append(ips, ip)
		}
	}
	return ips
}

// Browse for hostnames running the given service
func (m *mdns) Browse(service string, resolvePorts bool) []string {
	ptrs := make(chan dns.RR, 0)
	srvs := make(chan dns.RR, 0)
	wg := &sync.WaitGroup{}
	m.queries <- &query{
		questions: []dns.Question{
			dns.Question{service + ".local.", dns.TypePTR, dns.ClassINET},
		},
		results: ptrs,
	}

	hostset := map[string]bool{}
	hosts := []string{}
	for rr := range ptrs {
		switch rr := rr.(type) {
		case *dns.PTR:
			h := strings.Replace(rr.Ptr, rr.Header().Name, "", -1)
			if _, ok := hostset[h]; !ok {
				hostset[h] = true
				hosts = append(hosts, h)
			}
			if resolvePorts {
				res := make(chan dns.RR)
				m.queries <- &query{
					questions: []dns.Question{
						dns.Question{h + service + ".local.", dns.TypeSRV, dns.ClassINET},
					},
					results: res,
				}
				wg.Add(1)
				go func() {
					for srv := range res {
						srvs <- srv
					}
					wg.Done()
				}()
			}
		}
	}

	if resolvePorts {
		portset := map[string]bool{}
		ports := []string{}
		go func() {
			wg.Wait()
			close(srvs)
		}()
		for rr := range srvs {
			switch rr := rr.(type) {
			case *dns.SRV:
				k := rr.Target + ":" + strconv.Itoa(int(rr.Port))
				if _, ok := portset[k]; !ok {
					portset[k] = true
					ports = append(ports, k)
				}
			}
		}
		return ports
	} else {
		return hosts
	}
}

func (m *mdns) Shutdown() {
	close(m.exit)
}

// Main loop:
// - Reads questions, looks up in the local RRs and submits answers
// - Reads user queries, submits a request
func (m *mdns) loop(in chan msg) {
	var timeout <-chan time.Time
	for {
		select {
		case msg := <-in:
			if len(msg.Question) > 0 {
				// This is an incoming request from another host, try to send a reply
				msg.MsgHdr.Response = true
				for _, qst := range msg.Question {
					for _, rr := range m.match(qst) {
						msg.Answer = append(msg.Answer, rr)
					}
				}
				if len(msg.Answer) > 0 {
					msg.Question = nil
					m.write(msg)
				}
			} else {
				// This might be a reply to user dns request
				for _, rr := range msg.Answer {
					var results chan dns.RR
					for _, query := range m.pending {
						for _, q := range query.questions {
							if rr.Header().Name == q.Name {
								results = query.results
								break
							}
						}
					}
					if results == nil {
						continue
					}
					results <- rr
				}
			}
		case query := <-m.queries:
			query.timeout = time.After(time.Millisecond * 500)
			if len(m.pending) == 0 {
				timeout = query.timeout
			}
			m.pending = append(m.pending, query)
			m.write(msg{
				&dns.Msg{
					Question: query.questions,
				}, ipv4mcastaddr, m.connv4,
			})
			m.write(msg{
				&dns.Msg{
					Question: query.questions,
				}, ipv6mcastaddr, m.connv6,
			})
		case <-timeout:
			close(m.pending[0].results)
			m.pending = m.pending[1:]
			if len(m.pending) > 0 {
				timeout = m.pending[0].timeout
			} else {
				timeout = nil
			}
		case <-m.exit:
			m.connv4.Close()
			m.connv6.Close()
			return
		}
	}
}

func (m *mdns) match(q dns.Question) []dns.RR {
	rrs := []dns.RR{}
	for _, rr := range m.local[q.Name] {
		if q.Qtype == dns.TypeANY || q.Qtype == rr.Header().Rrtype {
			rrs = append(rrs, rr)
		}
	}
	return rrs
}

// A loop that reads incoming mDNS questions from UDP connection
// and passes them into the main loop question channel
func (m *mdns) readloop(c *net.UDPConn, in chan msg) {
	buf := make([]byte, 1500)
	for {
		if n, addr, err := c.ReadFromUDP(buf); err != nil {
			return
		} else {
			var dnsmsg dns.Msg
			if err := dnsmsg.Unpack(buf[:n]); err == nil {
				in <- msg{&dnsmsg, addr, c}
			}
		}
	}
}

// Writes question reply into the UDP connection
func (m *mdns) write(msg msg) {
	if buf, err := msg.Pack(); err == nil {
		msg.UDPConn.WriteToUDP(buf, msg.UDPAddr)
	}
}
