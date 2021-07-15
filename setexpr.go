// +build linux

package nftlib

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"net"
	"strconv"
	"strings"
)

// ipNetNextRange 给定一个 net.IPNet 网段，如192.168.1.0/22
// 分解出其当前网段与下一个网段地址，如 192.168.1.0 , 192.168.4.0 , ipv6与ipv4通用
func ipNetNextRange(netw net.IPNet) (net.IP, net.IP) {
	start := netw.IP
	ones, _ := netw.Mask.Size()
	bp := ones / 8
	bm := ones % 8
	if bm == 0 {
		bp -= 1
		bm = 8
	}
	end := make(net.IP, len(start))
	copy(end, start)
	end[bp] = end[bp] + 1<<(8-bm)
	return start, end
}

func ipAddrNext(ip net.IP) net.IP {
	ipnew := make(net.IP, len(ip))
	copy(ipnew, ip)
	for i := len(ipnew) - 1; i >= 0; i-- {
		if ipnew[i] == 255 {
			ipnew[i] = 0
			continue
		}
		ipnew[i] += 1
		break
	}
	return ipnew
}

func ipAddrPrev(ip net.IP) net.IP {
	ipnew := make(net.IP, len(ip))
	copy(ipnew, ip)
	for i := len(ipnew) - 1; i >= 0; i-- {
		if ipnew[i] == 0 {
			ipnew[i] = 255
			continue
		}
		ipnew[i] -= 1
		break
	}
	return ipnew
}

func calcTwoIpMask(start, end net.IP) int {
	var mlen int
	for i := 0; i < len(start); i++ {
		if start[i] == end[i] {
			mlen += 8
			continue
		}
		goal := false
		for j := 7; j >= 0; j-- {
			if end[i]-start[i] == 1<<j && start[i]%(1<<j) == 0 {
				mlen += 8 - j
				goal = true
				break
			}
		}
		if !goal {
			mlen = 0
		}
		break
	}
	return mlen
}

func setElemIpRange(nelems []nftables.SetElement) []string {
	var r []string
	if len(nelems) < 2 {
		return nil
	}
	for i := len(nelems) - 2; i >= 0; i -= 2 {
		if !(nelems[i].IntervalEnd == false && nelems[i-1].IntervalEnd == true) {
			return nil
		}
		start := net.IP(nelems[i].Key)
		end := net.IP(nelems[i-1].Key)
		if start.To4() != nil {
			start = start.To4()
		}
		if end.To4() != nil {
			end = end.To4()
		}
		if start == nil || end == nil {
			return nil
		}
		if start.Equal(ipAddrPrev(end)) {
			r = append(r, start.String())
			continue
		}
		mlen := calcTwoIpMask(start, end)
		if mlen != 0 {
			r = append(r, fmt.Sprintf("%s/%d", start, mlen))
			continue
		}
		r = append(r, fmt.Sprintf("%s-%s", start, ipAddrPrev(end)))
	}
	return r
}

func setElemIp(nelems []nftables.SetElement) []string {
	var r []string
	for i := len(nelems) - 1; i >= 0; i-- {
		ip := net.IP(nelems[i].Key)
		if ip.To4() != nil {
			ip = ip.To4()
		}
		if ip != nil {
			r = append(r, ip.String())
		}
	}
	return r
}

func setElemPort(nelems []nftables.SetElement) []string {
	var r []string
	for i := len(nelems) - 1; i > 0; i-- {
		port := binary.BigEndian.Uint16(nelems[i].Key)
		r = append(r, fmt.Sprintf("%d", port))
	}
	return r
}

func setElemPortRange(nelems []nftables.SetElement) []string {
	var r []string
	if len(nelems) < 3 {
		return nil
	}
	for i := len(nelems) - 2; i > 0; i -= 2 {
		if !(nelems[i].IntervalEnd == false && nelems[i-1].IntervalEnd == true) {
			return nil
		}
		start := binary.BigEndian.Uint16(nelems[i].Key)
		end := binary.BigEndian.Uint16(nelems[i-1].Key) - 1
		if start == end {
			r = append(r, fmt.Sprintf("%d", start))
			continue
		}
		if start < end {
			r = append(r, fmt.Sprintf("%d-%d", start, end))
		}
	}
	return r
}

func setNElemIp(elems []string) ([]nftables.SetElement, error) {
	var r []nftables.SetElement
	for _, v := range elems {
		if ip := net.ParseIP(v); ip != nil {
			if ip.To4() != nil {
				ip = ip.To4()
			}
			r = append([]nftables.SetElement{{Key: ip}}, r...)
			continue
		}
		return nil, errors.New(fmt.Sprintf("parse ip nelem failed, wrong ip format,ip=%s", v))
	}
	return r, nil
}

func setNElemIpRange(elems []string) ([]nftables.SetElement, error) {
	var r []nftables.SetElement
	for _, v := range elems {
		if strings.Contains(v, "-") {
			ipl := strings.Split(v, "-")
			if len(ipl) != 2 {
				return nil, errors.New(fmt.Sprintf("parse ip range nelem failed, wrong ip list length,ip=%s", v))
			}
			start := net.ParseIP(ipl[0])
			end := net.ParseIP(ipl[1])
			if start.To4() != nil && end.To4() != nil {
				start = start.To4()
				end = end.To4()
			}
			if start == nil || end == nil {
				return nil, errors.New(fmt.Sprintf("parse ip range nelem failed, wrong ip format,ip=%s", v))
			}
			r = append(r,
				nftables.SetElement{Key: start, IntervalEnd: false},
				nftables.SetElement{Key: ipAddrNext(end), IntervalEnd: true},
			)
			continue
		}
		if strings.Contains(v, "/") {
			_, netw, err := net.ParseCIDR(v)
			if err != nil {
				return nil, err
			}
			start, end := ipNetNextRange(*netw)
			r = append(r,
				nftables.SetElement{Key: start, IntervalEnd: false},
				nftables.SetElement{Key: end, IntervalEnd: true},
			)
			continue
		}
		if ip := net.ParseIP(v); ip != nil {
			if ip.To4() != nil {
				ip = ip.To4()
			}
			r = append(r,
				nftables.SetElement{Key: ip, IntervalEnd: false},
				nftables.SetElement{Key: ipAddrNext(ip), IntervalEnd: true},
			)
			continue
		}
		return nil, errors.New(fmt.Sprintf("parse ip range nelem failed, wrong range format,ip=%s", v))
	}

	return r, nil
}

func setNElemPort(elems []string) ([]nftables.SetElement, error) {
	var r []nftables.SetElement
	for _, v := range elems {
		port, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return nil, err
		}
		r = append([]nftables.SetElement{{Key: binaryutil.BigEndian.PutUint16(uint16(port))}}, r...)
	}
	return r, nil
}

func setNElemPortRange(elems []string) ([]nftables.SetElement, error) {
	var r []nftables.SetElement
	for _, v := range elems {
		if strings.Contains(v, "-") {
			pl := strings.Split(v, "-")
			if len(pl) != 2 {
				return nil, errors.New(
					fmt.Sprintf("parse port range nelem failed, wrong ip list length,ip=%s", v))
			}
			start, err := strconv.ParseUint(pl[0], 10, 16)
			if err != nil {
				return nil, err
			}
			end, err := strconv.ParseUint(pl[1], 10, 16)
			if err != nil {
				return nil, err
			}
			if !(end > start) {
				return nil, errors.New(fmt.Sprintf("parse port range nelem failed, !end>start,ip=%s", v))
			}
			r = append(r,
				nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(uint16(start)), IntervalEnd: false},
				nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(uint16(end) + 1), IntervalEnd: true},
			)
			continue
		}
		port, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return nil, err
		}
		r = append(r,
			nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(uint16(port)), IntervalEnd: false},
			nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(uint16(port) + 1), IntervalEnd: true},
		)
	}
	return r, nil
}

func setElemToNElem(dtype string, interval bool, elems []string) ([]nftables.SetElement, error) {
	var nelems []nftables.SetElement
	if interval {
		switch dtype {
		case SetDtypeIpv4:
			fallthrough
		case SetDtypeIpv6:
			nems, err := setNElemIpRange(elems)
			if err != nil {
				return nil, err
			}

			nelems = append(nelems, nems...)
			break
		case SetDtypePort:
			nems, err := setNElemPortRange(elems)
			if err != nil {
				return nil, err
			}
			nelems = append(nelems, nems...)
		}
		return nelems, nil
	}

	if !interval {
		switch dtype {
		case SetDtypeIpv4:
			fallthrough
		case SetDtypeIpv6:
			nems, err := setNElemIp(elems)
			if err != nil {
				return nil, err
			}
			nelems = append(nelems, nems...)
			break
		case SetDtypePort:
			nems, err := setNElemPort(elems)
			if err != nil {
				return nil, err
			}
			nelems = append(nelems, nems...)
			break
		}
	}
	return nelems, nil
}
