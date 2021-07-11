// +build linux

package nftlib

import (
	"errors"
	"fmt"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"net"
	"strconv"
	"strings"
)

// parseIpv4Expr offset=12为源IP,offset=16为目标IP
func parseIpv4Expr(ipaddr string, offset uint32) ([]expr.Any, error) {
	var (
		r       []expr.Any
		pldExpr = &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offset,
			Len:          4,
		}
	)
	if strings.Contains(ipaddr, "/") {
		_, netw, err := net.ParseCIDR(ipaddr)
		if err != nil {
			return nil, err
		}
		if len(netw.IP) == net.IPv4len {
			r = append(r, pldExpr,
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           netw.Mask,
					Xor:            make([]byte, 4),
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     netw.IP,
				},
			)
		} else {
			return nil, errors.New(fmt.Sprintf("parse ip failed, cidr format mismatch,ip=%s", ipaddr))
		}
		return r, nil
	}

	if strings.Contains(ipaddr, "-") {
		l := strings.Split(ipaddr, "-")
		if len(l) != 2 {
			return nil, errors.New(fmt.Sprintf("parse ip failed, range format mismatch,ip=%s", ipaddr))
		}
		start := net.ParseIP(l[0]).To4()
		end := net.ParseIP(l[1]).To4()
		if start != nil && end != nil {
			r = append(r, pldExpr,
				&expr.Range{
					Op:       expr.CmpOpEq,
					Register: 1,
					FromData: start,
					ToData:   end,
				},
			)
		} else {
			return nil, errors.New(fmt.Sprintf("parse ip failed, range format mismatch,ip=%s", ipaddr))
		}
		return r, nil
	}

	if ip := net.ParseIP(ipaddr).To4(); ip != nil {
		r = append(r, pldExpr,
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ip,
			},
		)
		return r, nil
	}

	if !strings.ContainsAny(ipaddr, "./-: ") {
		r = append(r, pldExpr,
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        ipaddr,
			},
		)
		return r, nil
	}
	return nil, errors.New(fmt.Sprintf("parse ip failed, format mismatch,ip=%s", ipaddr))
}

// parseIpv6Expr offset=8为源IP,offset=24为目标IP
func parseIpv6Expr(ipaddr string, offset uint32) ([]expr.Any, error) {
	var (
		r       []expr.Any
		pldExpr = &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offset,
			Len:          16,
		}
	)
	if strings.Contains(ipaddr, "/") {
		_, netw, err := net.ParseCIDR(ipaddr)
		if err != nil {
			return nil, err
		}
		if len(netw.IP) == net.IPv6len {
			r = append(r, pldExpr,
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            16,
					Mask:           netw.Mask,
					Xor:            make([]byte, 16),
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     netw.IP,
				},
			)
		} else {
			return nil, errors.New(fmt.Sprintf("parse ipv6 failed, cidr format mismatch,ip=%s", ipaddr))
		}
		return r, nil
	}

	if strings.Contains(ipaddr, "-") {
		l := strings.Split(ipaddr, "-")
		if len(l) != 2 {
			return nil, errors.New(fmt.Sprintf("parse ipv6 failed, ip range format mismatch,ip=%s", ipaddr))
		}
		start := net.ParseIP(l[0])
		end := net.ParseIP(l[1])
		if start != nil && end != nil && start.To4() == nil && end.To4() == nil {
			r = append(r, pldExpr,
				&expr.Range{
					Op:       expr.CmpOpEq,
					Register: 1,
					FromData: start,
					ToData:   end,
				},
			)
		} else {
			return nil, errors.New(fmt.Sprintf("parse ipv6 failed, ip range format mismatch,ip=%s", ipaddr))
		}
		return r, nil
	}

	if ip := net.ParseIP(ipaddr); ip != nil {
		if ip.To4() == nil {
			r = append(r, pldExpr,
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     ip,
				},
			)
		} else {
			return nil, errors.New(fmt.Sprintf("parse ipv6 failed, its a ipv4 address,ip=%s", ipaddr))
		}
		return r, nil
	}

	if !strings.ContainsAny(ipaddr, "./-: ") {
		r = append(r, pldExpr,
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        ipaddr,
			},
		)
		return r, nil
	}

	return nil, errors.New(fmt.Sprintf("parse ipv6 failed, format mismatch,ip=%s", ipaddr))
}

// parsePortExpr offset=0为源端口,offset=2为目标端口,UDP与TCP通用
func parsePortExpr(port string, offset uint32) ([]expr.Any, error) {
	var (
		r       []expr.Any
		pldExpr = &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Len:          2,
			Offset:       offset,
		}
	)
	if strings.Contains(port, "-") {
		l := strings.Split(port, "-")
		if len(l) != 2 {
			return nil, errors.New(fmt.Sprintf("parse port expr error,range length mismatch,port=%s", port))
		}
		start, err := strconv.ParseUint(l[0], 10, 16)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("parse port expr error,range start mismatch,port=%s", port))
		}
		end, err := strconv.ParseUint(l[1], 10, 16)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("parse port expr error,range end mismatch,port=%s", port))
		}
		if !(end > start) {
			return nil, errors.New(fmt.Sprintf("parse port expr error,range end must gt start,port=%s", port))
		}
		r = append(r, pldExpr,
			&expr.Range{
				Op:       expr.CmpOpEq,
				Register: 1,
				FromData: binaryutil.BigEndian.PutUint16(uint16(start)),
				ToData:   binaryutil.BigEndian.PutUint16(uint16(end)),
			},
		)
		return r, nil
	}

	if pt, err := strconv.ParseUint(port, 10, 16); err == nil {
		r = append(r, pldExpr,
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(uint16(pt)),
			},
		)
		return r, nil
	}

	if _, err := strconv.Atoi(port); !strings.ContainsAny(port, "./-: ") && err != nil {
		r = append(r, pldExpr,
			&expr.Lookup{
				SourceRegister: 1,
				Invert:         false,
				SetName:        port,
			},
		)
		return r, nil
	}

	return nil, errors.New(fmt.Sprintf("parse port expr error, format mismatch,port=%s", port))
}

func parseCtState(ctList []string) ([]expr.Any, error) {
	var (
		r   []expr.Any
		stt uint32
	)
	for kmp, vmp := range ctStateMap {
		for _, vl := range ctList {
			if vmp == vl {
				stt += kmp
			}
		}
	}
	if stt != 0 {
		r = append(r,
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(stt),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
		)
		return r, nil
	}
	return nil, errors.New(fmt.Sprintf("parse ct state error,ct=%v", ctList))
}
