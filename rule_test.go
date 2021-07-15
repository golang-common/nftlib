// +build linux

package nftlib

import (
	"fmt"
	"testing"
)

func TestRuleList(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	ch, err := tbl.GetChainByName("mychain")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := ch.ListRule()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(IndentJson(rules))
}

func TestRule_Regular(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	conn.FlushRuleset()
	tbl := conn.ADDTable(&Table{Name: "mytable", Family: TableFamilyInet})
	ch := tbl.AddBaseChain(&Chain{
		Name:   "mychain",
		Hook:   ChainHookInput,
		Type:   ChainTypeFilter,
		Policy: ChainPolicyDrop,
	})
	err = ch.AddRule(&Rule{
		L3Proto: RuleL3Ip,
		L3DstIP: "1.1.1.1",
		Action:  "accept",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = ch.AddRule(&Rule{
		L3Proto: RuleL3Ip,
		L3SrcIP: "172.21.194.11",
		Action:  "accept",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = ch.AddRule(&Rule{
		L3Proto: RuleL3Ip,
		L3SrcIP: "172.21.194.11",
		Action:  "drop",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = conn.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRule_Add(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	ch, err := tbl.GetChainByName("mychain")
	if err != nil {
		t.Fatal(err)
	}
	err = ch.AddRule(&Rule{
		L3Proto: RuleL3Ip,
		L3SrcIP: "2.2.2.45",
		Action:  "drop",
	})
	err = conn.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRule_AddMany(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	ch, err := tbl.GetChainByName("mychain")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		err = ch.AddRule(&Rule{
			L3Proto: RuleL3Ip,
			L3SrcIP: fmt.Sprintf("1.1.1.%d", i),
			Action:  "drop",
		})
	}
	err = conn.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRule_Replace(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	ch, err := tbl.GetChainByName("mychain")
	if err != nil {
		t.Fatal(err)
	}
	err = ch.ReplaceRule(&Rule{
		Handle:  6,
		L3Proto: RuleL3Ip,
		L3SrcIP: "9.9.9.9",
		Action:  "drop",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = conn.Commit()
	if err != nil {
		t.Fatal(err)
	}
}
