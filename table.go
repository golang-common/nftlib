// +build linux

package nftlib

import (
	"errors"
	"github.com/google/nftables"
	"net"
)

const (
	TableFamilyInet   tableFamily = "inet"
	TableFamilyIpv4   tableFamily = "ipv4"
	TableFamilyIpv6   tableFamily = "ipv6"
	TableFamilyBridge tableFamily = "bridge"
)

type tableFamily string

type Table struct {
	conn   *Conn       `json:"-"`
	Name   string      `json:"name"`
	Family tableFamily `json:"family"`
}

func (d *Table) AddSet(name, dtype string, drange bool, elems ...string) (*Set, error) {
	nset, err := d.conn.GetSetByName(d.toNTable(), name)
	if err == nil && nset != nil {
		return nil, errors.New("named set already exist")
	}
	var nsrv = nftables.TypeInvalid
	if v, ok := dtypeList[dtype]; ok {
		nsrv = v
	}
	if nsrv == nftables.TypeInvalid {
		return nil, errors.New("invalid datatype")
	}
	set := &Set{Name: name, conn: d.conn, Table: d, DType: dtype, Elements: elems, ElemRange: drange}
	nset, nelems, err := set.toNSet()
	if err != nil {
		return nil, err
	}
	if len(nelems) > 0 && drange {
		switch dtype {
		case SetDtypeIpv4:
			nelems = append([]nftables.SetElement{{Key: make([]byte, net.IPv4len), IntervalEnd: true}}, nelems...)
		case SetDtypeIpv6:
			nelems = append([]nftables.SetElement{{Key: make([]byte, net.IPv6len), IntervalEnd: true}}, nelems...)
		case SetDtypePort:
			nelems = append([]nftables.SetElement{{Key: make([]byte, 2), IntervalEnd: true}}, nelems...)
		}
	}

	err = d.conn.AddSet(nset, nelems)
	if err != nil {
		return nil, err
	}
	return set, nil
}

func (d *Table) GetSetByName(name string) (*Set, error) {
	nset, err := d.conn.GetSetByName(d.toNTable(), name)
	if err != nil {
		return nil, err
	}
	nelems, err := d.conn.GetSetElements(nset)
	if err != nil {
		return nil, err
	}
	set := &Set{conn: d.conn, Table: d}
	err = set.toSet(*nset, nelems...)
	if err != nil {
		return nil, err
	}
	return set, nil
}

func (d *Table) DelSet(set *Set) error {
	nset, _, err := set.toNSet()
	if err != nil {
		return err
	}
	d.conn.DelSet(nset)
	return nil
}

func (d *Table) ListSet() ([]*Set, error) {
	var setList []*Set
	nsets, err := d.conn.GetSets(d.toNTable())
	if err != nil {
		return nil, err
	}
	for _, nset := range nsets {
		nelems, err := d.conn.GetSetElements(nset)
		if err != nil {
			return nil, err
		}
		set := &Set{conn: d.conn, Table: d}
		err = set.toSet(*nset, nelems...)
		if err != nil {
			return nil, err
		}
		setList = append(setList, set)
	}
	return setList, nil
}

// ClearSet 清除所有没被使用的集合
func (d *Table) ClearSet() error {
	sets, err := d.ListSet()
	if err != nil {
		return err
	}
	for _, set := range sets {
		nset, _, err := set.toNSet()
		if err != nil {
			return err
		}
		d.conn.DelSet(nset)
	}
	return nil
}

func (d *Table) GetChainByName(name string) (*Chain, error) {
	nch, err := d.conn.ListChains()
	if err != nil {
		return nil, err
	}
	for _, nc := range nch {
		if nc.Name == name && nc.Table.Name == d.Name {
			ch := &Chain{conn: d.conn, Table: d}
			ch.toCh(*nc)
			return ch, nil
		}
	}
	return nil, errors.New("not found")
}

func (d *Table) ListChain() ([]*Chain, error) {
	var chs []*Chain
	nchs, err := d.conn.ListChains()
	if err != nil {
		return nil, err
	}
	for _, nch := range nchs {
		if nch.Table.Name == d.Name {
			ch := &Chain{Table: d, conn: d.conn}
			ch.toCh(*nch)
			chs = append(chs, ch)
		}
	}
	return chs, nil
}

func (d *Table) AddBaseChain(chain *Chain) *Chain {
	chain.conn = d.conn
	chain.Table = d
	nch := chain.toNch()
	d.conn.AddChain(nch)
	return chain
}

func (d *Table) AddRegularChain(name string) (*Chain, error) {
	n, err := d.GetChainByName(name)
	if err == nil && n != nil {
		return nil, errors.New("named chain already exist")
	}
	ch := &Chain{
		conn:  d.conn,
		Table: d,
		Name:  name,
	}
	nch := ch.toNch()
	d.conn.AddChain(nch)
	return ch, nil
}

func (d *Table) toTable(nTable nftables.Table) error {
	switch nTable.Family {
	case nftables.TableFamilyINet:
		d.Name = nTable.Name
		d.Family = TableFamilyInet
	case nftables.TableFamilyIPv4:
		d.Name = nTable.Name
		d.Family = TableFamilyIpv4
	case nftables.TableFamilyIPv6:
		d.Name = nTable.Name
		d.Family = TableFamilyIpv6
	case nftables.TableFamilyBridge:
		d.Name = nTable.Name
		d.Family = TableFamilyBridge
	}
	if d.Name == "" {
		return errors.New("toTable failed: nil table name")
	}
	if d.Family == "" {
		return errors.New("toTable failed: nil table family")
	}
	return nil
}

func (d *Table) toNTable() *nftables.Table {
	var ntbl = new(nftables.Table)
	ntbl.Name = d.Name
	switch d.Family {
	case TableFamilyInet:
		ntbl.Family = nftables.TableFamilyINet
	case TableFamilyIpv4:
		ntbl.Family = nftables.TableFamilyIPv4
	case TableFamilyIpv6:
		ntbl.Family = nftables.TableFamilyIPv6
	case TableFamilyBridge:
		ntbl.Family = nftables.TableFamilyBridge
	}
	return ntbl
}
