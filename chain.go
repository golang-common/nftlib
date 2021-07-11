// +build linux

package nftlib

import (
	"errors"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
)

const (
	ChainHookInput   chainHook = "input"
	ChainHookOutput  chainHook = "output"
	ChainHookForward chainHook = "forward"

	ChainTypeFilter chainType = "filter"
	ChainTypeRoute  chainType = "route"
	ChainTypeNat    chainType = "nat"

	ChainPolicyAccept chainPolicy = "accept"
	ChainPolicyDrop   chainPolicy = "drop"
)

type Chain struct {
	conn   *Conn       `json:"-"`
	Table  *Table      `json:"table,omitempty"`
	Name   string      `json:"name,omitempty"`
	Hook   chainHook   `json:"hook,omitempty"`
	Type   chainType   `json:"type,omitempty"`
	Policy chainPolicy `json:"policy,omitempty"`
}

type (
	chainHook   string
	chainType   string
	chainPolicy string
)

func (d *Chain) NewRule() *Rule {
	return &Rule{Chain: d, conn: d.conn}
}

func (d *Chain) AddRule(rule *Rule) error {
	nrule, err := rule.toNRule()
	if err != nil {
		return err
	}
	d.conn.AddRule(nrule)
	return nil
}

func (d *Chain) DelRule(rule *Rule) error {
	nrule, err := rule.toNRule()
	if err != nil {
		return err
	}
	err = d.conn.DelRule(nrule)
	if err != nil {
		return err
	}
	return nil
}

func (d *Chain) ReplaceRule(rule *Rule) error {
	nrule, err := rule.toNRule()
	if err != nil {
		return err
	}
	d.conn.ReplaceRule(nrule)
	return nil
}

func (d *Chain) ListRule() ([]*Rule, error) {
	var r []*Rule
	nrlist, err := d.conn.GetRule(d.Table.toNTable(), d.toNch())
	if err != nil {
		return nil, err
	}
	for _, nr := range nrlist {
		rule := &Rule{Chain: d, conn: d.conn}
		err = rule.toRule(*nr)
		if err != nil {
			return nil, err
		}
		r = append(r, rule)
	}
	return r, nil
}

func (d *Chain) Commit() error {
	return d.conn.Commit()
}

func (d *Chain) toCh(nch nftables.Chain) error {
	d.Name = nch.Name
	switch nch.Type {
	case nftables.ChainTypeFilter:
		d.Type = ChainTypeFilter
	case nftables.ChainTypeRoute:
		d.Type = ChainTypeRoute
	case nftables.ChainTypeNAT:
		d.Type = ChainTypeNat
	default:
		return errors.New("to chain failed, empty chain type")
	}

	switch nch.Hooknum {
	case nftables.ChainHookInput:
		d.Hook = ChainHookInput
	case nftables.ChainHookOutput:
		d.Hook = ChainHookOutput
	case nftables.ChainHookForward:
		d.Hook = ChainHookForward
	default:
		return errors.New("to chain failed, empty chain hook")
	}

	plc := *nch.Policy
	plcb := binaryutil.BigEndian.PutUint32(uint32(plc))
	plcn := binaryutil.NativeEndian.Uint32(plcb)
	switch nftables.ChainPolicy(plcn) {
	case nftables.ChainPolicyAccept:
		d.Policy = ChainPolicyAccept
	case nftables.ChainPolicyDrop:
		d.Policy = ChainPolicyDrop
	default:
		return errors.New("to chain failed, empty chain policy")
	}
	return nil
}

func (d *Chain) toNch() *nftables.Chain {
	var nch = new(nftables.Chain)
	nch.Name = d.Name
	nch.Table = d.Table.toNTable()
	switch d.Type {
	case ChainTypeFilter:
		nch.Type = nftables.ChainTypeFilter
	case ChainTypeRoute:
		nch.Type = nftables.ChainTypeRoute
	case ChainTypeNat:
		nch.Type = nftables.ChainTypeNAT
	}
	switch d.Hook {
	case ChainHookOutput:
		nch.Hooknum = nftables.ChainHookOutput
	case ChainHookInput:
		nch.Hooknum = nftables.ChainHookInput
	case ChainHookForward:
		nch.Hooknum = nftables.ChainHookForward
	}
	switch d.Policy {
	case ChainPolicyAccept:
		plc := nftables.ChainPolicyAccept
		nch.Policy = &plc
	case ChainPolicyDrop:
		plc := nftables.ChainPolicyDrop
		nch.Policy = &plc
	}
	return nch
}
