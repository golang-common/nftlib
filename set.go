// +build linux

package nftlib

import (
	"errors"
	"github.com/google/nftables"
)

const (
	SetDtypeIpv4 = "ipv4"
	SetDtypeIpv6 = "ipv6"
	SetDtypePort = "port"
)

var (
	dtypeList = map[string]nftables.SetDatatype{
		SetDtypeIpv4: nftables.TypeIPAddr,
		SetDtypeIpv6: nftables.TypeIP6Addr,
		SetDtypePort: nftables.TypeInetService,
	}
)

type Set struct {
	conn      *Conn
	Table     *Table   `json:"table"`
	Name      string   `json:"name,omitempty"`
	DType     string   `json:"dtype,omitempty"`
	ElemRange bool     `json:"elemrange"`
	Elements  []string `json:"elements,omitempty"`
}

func (d *Set) AddElements(elems ...string) error {
	nset, _, err := d.toNSet()
	if err != nil {
		return err
	}
	nelems, err := setElemToNElem(d.DType, d.ElemRange, elems)
	if err != nil {
		return err
	}
	err = d.conn.SetAddElements(nset, nelems)
	if err != nil {
		return err
	}
	return nil
}

func (d *Set) DelElements(elems ...string) error {
	nset, _, err := d.toNSet()
	if err != nil {
		return err
	}

	nelems, err := setElemToNElem(d.DType, d.ElemRange, elems)
	if err != nil {
		return err
	}
	err = d.conn.SetDeleteElements(nset, nelems)
	if err != nil {
		return err
	}
	return nil
}

func (d *Set) Commit() error {
	return d.conn.Commit()
}

func (d *Set) Flush() error {
	ns, _, err := d.toNSet()
	if err != nil {
		return err
	}
	d.conn.FlushSet(ns)
	return nil
}

func (d *Set) toSet(set nftables.Set, elems ...nftables.SetElement) error {
	d.Name = set.Name
	for k, v := range dtypeList {
		if set.KeyType.GetNFTMagic() == v.GetNFTMagic() && set.KeyType.GetNFTMagic() != 0 {
			d.DType = k
			break
		}
	}
	d.ElemRange = set.Interval
	if d.DType == "" {
		return errors.New("unsupport data type")
	}
	if len(elems) == 0 {
		return nil
	}
	// 解析范围类型值
	if d.ElemRange {
		switch d.DType {
		case SetDtypeIpv4:
			fallthrough
		case SetDtypeIpv6:
			d.Elements = setElemIpRange(elems)
			return nil
		case SetDtypePort:
			d.Elements = setElemPortRange(elems)
		}
	}
	// 解析非范围类型值
	if !d.ElemRange {
		switch d.DType {
		case SetDtypeIpv4:
			fallthrough
		case SetDtypeIpv6:
			d.Elements = setElemIp(elems)
			return nil
		case SetDtypePort:
			d.Elements = setElemPort(elems)
		}
	}
	return nil
}

func (d *Set) toNSet() (*nftables.Set, []nftables.SetElement, error) {
	var (
		nset   = new(nftables.Set)
		nelems []nftables.SetElement
		err    error
	)
	nset.Table = d.Table.toNTable()
	nset.Name = d.Name
	nset.Interval = d.ElemRange
	ktype, ok := dtypeList[d.DType]
	if !ok {
		return nil, nil, errors.New("unsupport key data type")
	}
	nset.KeyType = ktype

	if len(d.Elements) == 0 {
		return nset, nil, nil
	}

	nelems, err = setElemToNElem(d.DType, d.ElemRange, d.Elements)
	if err != nil {
		return nil, nil, err
	}

	return nset, nelems, nil
}
