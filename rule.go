// +build linux

package nftlib

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"net"
	"strconv"
)

const (
	RuleDireSrc = "src"
	RuleDireDst = "dst"

	RuleL3Ip    = "ipv4"
	RuleL3Ip6   = "ipv6"
	RuleL4Tcp   = "tcp"
	RuleL4Udp   = "udp"
	RuleL4Icmp  = "icmp"
	RuleL4Icmp6 = "icmp6"

	RuleActAccept = "accept"
	RuleActDrop   = "drop"
	RuleActJump   = "jump"
	RuleActGoto   = "goto"

	RuleCtInvalid     = "invalid"
	RuleCtEstablished = "established"
	RuleCtRelated     = "related"
	RuleCtNew         = "new"
	RuleCtUntracked   = "untracked"

	CtStateBitINVALID     uint32 = 1
	CtStateBitESTABLISHED uint32 = 2
	CtStateBitRELATED     uint32 = 4
	CtStateBitNEW         uint32 = 8
	CtStateBitUNTRACKED   uint32 = 64

	curMatchL3Proto  = "l3proto"
	curMatchL3SAddr  = "l3saddr"
	curMatchL3DAddr  = "l3daddr"
	curMatchL3SAddr6 = "l3saddr6"
	curMatchL3DAddr6 = "l3daddr6"
	curMatchL4Proto  = "l4proto"
	curMatchL4SPort  = "l4sport"
	curMatchL4DPort  = "l4dport"
	curMatchCtState  = "ctstate"
)

var (
	ctStateMap = map[uint32]string{
		CtStateBitINVALID:     RuleCtInvalid,
		CtStateBitESTABLISHED: RuleCtEstablished,
		CtStateBitRELATED:     RuleCtRelated,
		CtStateBitNEW:         RuleCtNew,
		CtStateBitUNTRACKED:   RuleCtUntracked,
	}
	actionMap = map[expr.VerdictKind]string{
		expr.VerdictAccept: RuleActAccept,
		expr.VerdictDrop:   RuleActDrop,
		expr.VerdictJump:   RuleActJump,
		expr.VerdictGoto:   RuleActGoto,
	}
)

type Rule struct {
	conn   *Conn  `json:"-"`
	Chain  *Chain `json:"chain,omitempty"`
	Index  uint64 `json:"index,omitempty"`
	Handle uint64 `json:"handle,omitempty"`
	// L3Proto ipv4 or ipv6
	L3Proto string `json:"l3proto,omitempty"`
	// SrcIP DstIP e.g.: 1.1.1.1 or 1.1.1.1-1.1.1.100 or 1.1.1.0/24 or setname
	L3SrcIP string `json:"src_ip,omitempty"`
	L3DstIP string `json:"dst_ip,omitempty"`
	// L4Proto tcp or udp
	L4Proto string `json:"l4proto,omitempty"`
	// SrcPort DstPort e.g.: 3306 or 3306-3307
	L4SrcPort string `json:"src_port,omitempty"`
	L4DstPort string `json:"dst_port,omitempty"`
	// CtStates one of [established,related,new,invalid,untracked]
	CtStates []string `json:"ct_states,omitempty"`
	// Action one of [accept,drop,jump,goto]
	Action string `json:"action,omitempty"`
	// DstChain chain of goto/jump action destination
	DstChain string `json:"dst_chain,omitempty"`
}

func (d *Rule) SetL3Proto(proto string) *Rule {
	d.L3Proto = proto
	return d
}

func (d *Rule) SetL3Ip(ip net.IP, dire string) *Rule {
	if ip != nil && (dire == RuleDireSrc || dire == RuleDireDst) {
		if ip.To4() != nil {
			d.L3Proto = RuleL3Ip
		} else {
			d.L3Proto = RuleL3Ip6
		}

		if dire == RuleDireSrc {
			d.L3SrcIP = ip.String()
		} else if dire == RuleDireDst {
			d.L3DstIP = ip.String()
		}
	}
	return d
}

func (d *Rule) SetL3IpRange(start, end net.IP, dire string) *Rule {
	if start != nil && end != nil && (dire == RuleDireSrc || dire == RuleDireDst) {
		if start.To4() != nil && end.To4() != nil {
			d.L3Proto = RuleL3Ip
		} else {
			d.L3Proto = RuleL3Ip6
		}

		if dire == RuleDireSrc {
			d.L3SrcIP = fmt.Sprintf("%s-%s", start.String(), end.String())
		} else if dire == RuleDireDst {
			d.L3DstIP = fmt.Sprintf("%s-%s", start.String(), end.String())
		}
	}
	return d
}

func (d *Rule) SetL3IpSet(name string, dire string) *Rule {
	if dire == RuleDireSrc {
		d.L3SrcIP = name
	} else if dire == RuleDireDst {
		d.L3DstIP = name
	}
	return d
}

func (d *Rule) SetL3IpCidr(ip net.IP, maskLen int, dire string) *Rule {
	if ip != nil && (dire == RuleDireSrc || dire == RuleDireDst) {
		if len(ip) == net.IPv4len && maskLen >= 0 && maskLen <= 32 {
			d.L3Proto = RuleL3Ip
		}
		if len(ip) == net.IPv6len && maskLen >= 0 && maskLen <= 128 {
			d.L3Proto = RuleL3Ip6
		}
		if dire == RuleDireSrc {
			d.L3SrcIP = fmt.Sprintf("%s/%d", ip.String(), maskLen)
		}
		if dire == RuleDireDst {
			d.L3DstIP = fmt.Sprintf("%s/%d", ip.String(), maskLen)
		}
	}
	return d
}

func (d *Rule) SetL4Proto(proto string) *Rule {
	d.L4Proto = proto
	return d
}

func (d *Rule) SetL4Port(port uint16, dire string) *Rule {
	if d.L4Proto != "" && (dire == RuleDireSrc || dire == RuleDireDst) {
		if dire == RuleDireSrc {
			d.L4SrcPort = strconv.FormatInt(int64(port), 10)
		} else if dire == RuleDireDst {
			d.L4DstPort = strconv.FormatInt(int64(port), 10)
		}
	}
	return d
}

func (d *Rule) SetL4PortRange(start, end uint16, dire string) *Rule {
	if d.L4Proto != "" && (dire == RuleDireSrc || dire == RuleDireDst) && end > start {
		if dire == RuleDireSrc {
			d.L4SrcPort = fmt.Sprintf("%d-%d", start, end)
		} else if dire == RuleDireDst {
			d.L4DstPort = fmt.Sprintf("%d-%d", start, end)
		}
	}
	return d
}

func (d *Rule) SetL4Set(name string, dire string) *Rule {
	if dire == RuleDireSrc {
		d.L4SrcPort = name
	} else if dire == RuleDireDst {
		d.L4DstPort = name
	}
	return d
}

func (d *Rule) SetCt(cts ...string) *Rule {
	d.CtStates = cts
	return d
}

func (d *Rule) SetAccept() *Rule {
	d.Action = RuleActAccept
	return d
}

func (d *Rule) SetDrop() *Rule {
	d.Action = RuleActDrop
	return d
}

func (d *Rule) SetJump(tochain string) *Rule {
	d.Action = RuleActJump
	d.DstChain = tochain
	return d
}

func (d *Rule) SetGoto(tochain string) *Rule {
	d.Action = RuleActGoto
	d.DstChain = tochain
	return d
}

// toRule 解析nftables规则到rule结构体
// TODO:toRule目前只返回nil错误，后续增加更完善的错误处理
func (d *Rule) toRule(nrule nftables.Rule) error {
	var (
		curMatch                         string
		curMask                          net.IPMask
		curRangeIpMin, curRangeIpMax     net.IP
		curRangePortMin, curRangePortMax uint16
	)
	d.Index = nrule.Position
	d.Handle = nrule.Handle
	for i := 0; i < len(nrule.Exprs); i++ {
		exp := nrule.Exprs[i]
		switch exp.(type) {
		case *expr.Meta:
			meta := exp.(*expr.Meta)
			if meta.Key == expr.MetaKeyNFPROTO {
				curMatch = curMatchL3Proto
				continue
			}
			if meta.Key == expr.MetaKeyL4PROTO {
				curMatch = curMatchL4Proto
				continue
			}
		case *expr.Cmp:
			cmp := exp.(*expr.Cmp)
			if curMatch == curMatchL3Proto {
				if bytes.Equal(cmp.Data, []byte{unix.NFPROTO_IPV4}) {
					d.L3Proto = RuleL3Ip
				} else if bytes.Equal(cmp.Data, []byte{unix.NFPROTO_IPV6}) {
					d.L3Proto = RuleL3Ip6
				}
				continue
			}
			if curMatch == curMatchL4Proto {
				if bytes.Equal(cmp.Data, []byte{unix.IPPROTO_TCP}) {
					d.L4Proto = RuleL4Tcp
				} else if bytes.Equal(cmp.Data, []byte{unix.IPPROTO_UDP}) {
					d.L4Proto = RuleL4Udp
				} else if bytes.Equal(cmp.Data, []byte{unix.IPPROTO_ICMP}) {
					d.L4Proto = RuleL4Icmp
				} else if bytes.Equal(cmp.Data, []byte{unix.IPPROTO_ICMPV6}) {
					d.L4Proto = RuleL4Icmp6
				}
				continue
			}
			if curMatch == curMatchL3SAddr || curMatch == curMatchL3SAddr6 {
				ip := net.IP(cmp.Data)
				switch cmp.Op {
				case expr.CmpOpGte:
					curRangeIpMin = ip
				case expr.CmpOpLte:
					curRangeIpMax = ip
				case expr.CmpOpEq:
					if curMask != nil {
						one, _ := curMask.Size()
						d.L3SrcIP = fmt.Sprintf("%s/%d", ip.String(), one)
						curMask = nil
					} else {
						d.L3SrcIP = ip.String()
					}
				}
				if curRangeIpMin != nil && curRangeIpMax != nil {
					d.L3SrcIP = fmt.Sprintf("%s-%s", curRangeIpMin, curRangeIpMax)
					curRangeIpMin = nil
					curRangeIpMax = nil
				}
				continue
			}
			if curMatch == curMatchL3DAddr || curMatch == curMatchL3DAddr6 {
				ip := net.IP(cmp.Data)
				switch cmp.Op {
				case expr.CmpOpGte:
					curRangeIpMin = ip
				case expr.CmpOpLte:
					curRangeIpMax = ip
				case expr.CmpOpEq:
					if curMask != nil {
						one, _ := curMask.Size()
						d.L3DstIP = fmt.Sprintf("%s/%d", ip.String(), one)
						curMask = nil
					} else {
						d.L3DstIP = ip.String()
					}
					continue
				}
				if curRangeIpMin != nil && curRangeIpMax != nil {
					d.L3DstIP = fmt.Sprintf("%s-%s", curRangeIpMin, curRangeIpMax)
					curRangeIpMin = nil
					curRangeIpMax = nil
				}
				continue
			}
			if curMatch == curMatchL4SPort {
				switch cmp.Op {
				case expr.CmpOpGte:
					curRangePortMin = binary.BigEndian.Uint16(cmp.Data)
				case expr.CmpOpLte:
					curRangePortMax = binary.BigEndian.Uint16(cmp.Data)
				case expr.CmpOpEq:
					d.L4SrcPort = fmt.Sprintf("%d", binary.BigEndian.Uint16(cmp.Data))
					continue
				}
				if curRangePortMin != 0 && curRangePortMax != 0 {
					d.L4SrcPort = fmt.Sprintf("%d-%d", curRangePortMin, curRangePortMax)
				}
				continue
			}
			if curMatch == curMatchL4DPort {
				switch cmp.Op {
				case expr.CmpOpGte:
					curRangePortMin = binary.BigEndian.Uint16(cmp.Data)
				case expr.CmpOpLte:
					curRangePortMax = binary.BigEndian.Uint16(cmp.Data)
				case expr.CmpOpEq:
					d.L4DstPort = fmt.Sprintf("%d", binary.BigEndian.Uint16(cmp.Data))
					continue
				}
				if curRangePortMin != 0 && curRangePortMax != 0 {
					d.L4DstPort = fmt.Sprintf("%d-%d", curRangePortMin, curRangePortMax)
				}
				continue
			}
		case *expr.Payload:
			pld := exp.(*expr.Payload)
			if pld.Base == expr.PayloadBaseNetworkHeader {
				if pld.Offset == 12 && pld.Len == 4 {
					curMatch = curMatchL3SAddr
				} else if pld.Offset == 16 && pld.Len == 4 {
					curMatch = curMatchL3DAddr
				} else if pld.Offset == 8 && pld.Len == 16 {
					curMatch = curMatchL3SAddr6
				} else if pld.Offset == 24 && pld.Len == 16 {
					curMatch = curMatchL3DAddr6
				}
				continue
			}
			if pld.Base == expr.PayloadBaseTransportHeader {
				if pld.Offset == 0 && pld.Len == 2 {
					curMatch = curMatchL4SPort
				} else if pld.Offset == 2 && pld.Len == 2 {
					curMatch = curMatchL4DPort
				}
				continue
			}
		case *expr.Bitwise:
			btw := exp.(*expr.Bitwise)
			if curMatch == curMatchL3SAddr || curMatch == curMatchL3DAddr ||
				curMatch == curMatchL3SAddr6 || curMatch == curMatchL3DAddr6 {
				curMask = btw.Mask
				continue
			}
			if curMatch == curMatchCtState {
				stateNum := binary.LittleEndian.Uint32(btw.Mask)
				for k, v := range ctStateMap {
					if stateNum&k == k {
						d.CtStates = append(d.CtStates, v)
					}
				}
				continue
			}
		case *expr.Range:
			rg := exp.(*expr.Range)
			if curMatch == curMatchL3SAddr {
				start := net.IP(rg.FromData[4:])
				end := net.IP(rg.ToData[4:])
				d.L3SrcIP = fmt.Sprintf("%s-%s", start.String(), end.String())
				continue
			}
			if curMatch == curMatchL3DAddr {
				start := net.IP(rg.FromData[4:])
				end := net.IP(rg.ToData[4:])
				d.L3DstIP = fmt.Sprintf("%s-%s", start.String(), end.String())
				continue
			}
			if curMatch == curMatchL3SAddr6 {
				start := net.IP(rg.FromData)
				end := net.IP(rg.ToData)
				d.L3SrcIP = fmt.Sprintf("%s-%s", start.String(), end.String())
			}
			if curMatch == curMatchL3DAddr6 {
				start := net.IP(rg.FromData[4:])
				end := net.IP(rg.ToData[4:])
				d.L3DstIP = fmt.Sprintf("%s-%s", start.String(), end.String())
			}
			if curMatch == curMatchL4SPort {
				start := binary.BigEndian.Uint16(rg.FromData[4:6])
				end := binary.BigEndian.Uint16(rg.ToData[4:6])
				d.L4SrcPort = fmt.Sprintf("%d-%d", start, end)
				continue
			}
			if curMatch == curMatchL4DPort {
				start := binary.BigEndian.Uint16(rg.FromData[4:6])
				end := binary.BigEndian.Uint16(rg.ToData[4:6])
				d.L4DstPort = fmt.Sprintf("%d-%d", start, end)
				continue
			}
		case *expr.Lookup:
			lp := exp.(*expr.Lookup)
			if curMatch == curMatchL3SAddr || curMatch == curMatchL3SAddr6 {
				d.L3SrcIP = lp.SetName
				continue
			}
			if curMatch == curMatchL3DAddr || curMatch == curMatchL3DAddr6 {
				d.L3DstIP = lp.SetName
				continue
			}
			if curMatch == curMatchL4SPort {
				d.L4SrcPort = lp.SetName
				continue
			}
			if curMatch == curMatchL4DPort {
				d.L4DstPort = lp.SetName
				continue
			}
		case *expr.Ct:
			ct := exp.(*expr.Ct)
			if ct.Key == expr.CtKeySTATE {
				curMatch = curMatchCtState
				continue
			}
		case *expr.Verdict:
			vd := exp.(*expr.Verdict)
			for k, v := range actionMap {
				if vd.Kind == k {
					d.Action = v
					if vd.Chain != "" {
						d.DstChain = vd.Chain
					}
					break
				}
			}
			continue
		}
	}
	return nil
}

func (d *Rule) toNRule() (*nftables.Rule, error) {
	var ntr = new(nftables.Rule)
	ntr.Table = d.Chain.Table.toNTable()
	ntr.Chain = d.Chain.toNch()
	// 解析L3协议
	if d.L3Proto != "" {
		switch d.L3Proto {
		case RuleL3Ip:
			ntr.Exprs = append(ntr.Exprs,
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
			)
		case RuleL3Ip6:
			ntr.Exprs = append(ntr.Exprs,
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
			)
		default:
			return nil, errors.New("wrong l3 protocol type")
		}
	}
	// 解析源IP
	if d.L3Proto == RuleL3Ip && d.L3SrcIP != "" {
		exprs, err := parseIpv4Expr(d.L3SrcIP, 12)
		if err != nil {
			return nil, err
		}
		ntr.Exprs = append(ntr.Exprs, exprs...)
	} else if d.L3Proto == RuleL3Ip6 && d.L3SrcIP != "" {
		exprs, err := parseIpv6Expr(d.L3SrcIP, 8)
		if err != nil {
			return nil, err
		}
		ntr.Exprs = append(ntr.Exprs, exprs...)
	}
	// 解析目标IP
	if d.L3Proto == RuleL3Ip && d.L3DstIP != "" {
		exprs, err := parseIpv4Expr(d.L3DstIP, 16)
		if err != nil {
			return nil, err
		}
		ntr.Exprs = append(ntr.Exprs, exprs...)
	} else if d.L3Proto == RuleL3Ip6 && d.L3DstIP != "" {
		exprs, err := parseIpv6Expr(d.L3DstIP, 24)
		if err != nil {
			return nil, err
		}
		ntr.Exprs = append(ntr.Exprs, exprs...)
	}
	// 解析l4协议
	if d.L4Proto != "" {
		switch d.L4Proto {
		case RuleL4Tcp:
			ntr.Exprs = append(ntr.Exprs,
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			)
		case RuleL4Udp:
			ntr.Exprs = append(ntr.Exprs,
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			)
		case RuleL4Icmp:
			ntr.Exprs = append(ntr.Exprs,
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMP}},
			)
		case RuleL4Icmp6:
			ntr.Exprs = append(ntr.Exprs,
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}},
			)
		}
	}
	// 解析源端口
	if (d.L4Proto == RuleL4Tcp || d.L4Proto == RuleL4Udp) && d.L4SrcPort != "" {
		exprs, err := parsePortExpr(d.L4SrcPort, 0)
		if err != nil {
			return nil, err
		}
		ntr.Exprs = append(ntr.Exprs, exprs...)
	}
	// 解析目标端口
	if (d.L4Proto == RuleL4Tcp || d.L4Proto == RuleL4Udp) && d.L4DstPort != "" {
		exprs, err := parsePortExpr(d.L4DstPort, 2)
		if err != nil {
			return nil, err
		}
		ntr.Exprs = append(ntr.Exprs, exprs...)
	}
	// 解析状态跟踪
	if len(d.CtStates) != 0 {
		exprs, err := parseCtState(d.CtStates)
		if err != nil {
			return nil, err
		}
		ntr.Exprs = append(ntr.Exprs, exprs...)
	}
	// 解析策略动作
	if d.Action != "" {
		switch d.Action {
		case RuleActAccept:
			ntr.Exprs = append(ntr.Exprs, &expr.Verdict{Kind: expr.VerdictAccept})
		case RuleActDrop:
			ntr.Exprs = append(ntr.Exprs, &expr.Verdict{Kind: expr.VerdictDrop})
		case RuleActGoto:
			ntr.Exprs = append(ntr.Exprs, &expr.Verdict{Kind: expr.VerdictGoto})
		case RuleActJump:
			ntr.Exprs = append(ntr.Exprs, &expr.Verdict{Kind: expr.VerdictJump})
		}
	}
	return ntr, nil
}
