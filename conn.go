// +build linux

package nftlib

import (
	"errors"
	"github.com/google/nftables"
	"github.com/vishvananda/netns"
)

func New(namespace ...string) (*Conn, error) {
	var (
		nsname string
		ns     netns.NsHandle
		err    error
	)
	if len(namespace) > 0 {
		nsname = namespace[0]
	}
	if nsname != "" {
		if ns, err = netns.GetFromName(nsname); err != nil {
			return nil, err
		}
	} else {
		ns, err = netns.Get()
	}
	return &Conn{Conn: &nftables.Conn{NetNS: int(ns)}}, nil
}

type Conn struct {
	*nftables.Conn
}

func (d *Conn) ADDTable(name string, family tableFamily) (*Table, error) {
	t, err := d.GetTableByName(name)
	if err == nil && t != nil {
		return nil, errors.New("named table already exist")
	}
	tbl := &Table{
		conn:   d,
		Name:   name,
		Family: family,
	}
	ntbl := tbl.toNTable()
	d.AddTable(ntbl)
	err = d.Commit()
	if err != nil {
		return nil, err
	}
	return tbl, nil
}

func (d *Conn) ShowTables() ([]*Table, error) {
	var tbl []*Table
	ntbl, err := d.ListTables()
	if err != nil {
		return nil, err
	}
	for _, ntb := range ntbl {
		t := &Table{conn: d}
		err = t.toTable(*ntb)
		if err != nil {
			return nil, err
		}
		tbl = append(tbl, t)
	}
	return tbl, nil
}

func (d *Conn) GetTableByName(tableName string) (*Table, error) {
	ntbl, err := d.Conn.ListTables()
	if err != nil {
		return nil, err
	}
	for _, ntb := range ntbl {
		if ntb.Name == tableName {
			t := &Table{conn: d}
			err = t.toTable(*ntb)
			if err != nil {
				return nil, err
			}
			return t, nil
		}
	}
	return nil, errors.New("not found")
}

func (d *Conn) ClearAll() {
	d.FlushRuleset()
}

func (d *Conn) Commit() error {
	err := d.Flush()
	return err
}

func (d *Conn) Discard() {
	d.Conn = &nftables.Conn{NetNS: d.NetNS}
}
