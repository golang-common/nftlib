// +build linux

package nftlib

import (
	"net"
	"testing"
)

func TestAddChain(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	err = tbl.AddBaseChain(&Chain{
		Name:   "mychain",
		Hook:   ChainHookInput,
		Type:   ChainTypeFilter,
		Policy: ChainPolicyAccept,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddRuleIpv4(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := tbl.GetChainByName("mychain")
	if err != nil {
		t.Fatal(err)
	}
	rule := chain.NewRule()
	rule.SetL3Proto(RuleL3Ip6)
	rule.SetL3Ip(net.ParseIP("192.168.1.1"), RuleDireDst)
	rule.SetAccept()

	err = chain.AddRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	err = chain.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddRuleIpv4Set(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := tbl.GetChainByName("mychain")
	if err != nil {
		t.Fatal(err)
	}
	rule := chain.NewRule()
	rule.SetL3Proto(RuleL3Ip)
	rule.SetL3IpSet("setipv4", RuleDireDst)
	rule.SetAccept()

	err = chain.AddRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	err = chain.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddRuleIpv6Set(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := tbl.GetChainByName("mychain")
	if err != nil {
		t.Fatal(err)
	}
	rule := chain.NewRule()
	rule.SetL3Proto(RuleL3Ip6)
	rule.SetL3IpSet("setipv6", RuleDireDst)
	rule.SetAccept()

	err = chain.AddRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	err = chain.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddRuleIpv4RangeSet(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := tbl.GetChainByName("mychain")
	if err != nil {
		t.Fatal(err)
	}
	rule := chain.NewRule()
	rule.SetL3Proto(RuleL3Ip6)
	rule.SetL3IpSet("setipv4range", RuleDireSrc)
	rule.SetAccept()

	err = chain.AddRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	err = chain.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddRuleIpv6RangeSet(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := tbl.GetChainByName("mychain")
	if err != nil {
		t.Fatal(err)
	}
	rule := chain.NewRule()
	rule.SetL3Proto(RuleL3Ip6)
	rule.SetL3IpSet("setipv6range", RuleDireDst)
	rule.SetAccept()

	err = chain.AddRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	err = chain.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddRulePort(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := tbl.GetChainByName("mychain")
	if err != nil {
		t.Fatal(err)
	}
	rule := chain.NewRule()
	rule.SetL4Proto(RuleL4Tcp)
	rule.SetL4Set("setport", RuleDireSrc)
	rule.SetAccept()

	err = chain.AddRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	err = chain.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddRulePortRange(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := tbl.GetChainByName("mychain")
	if err != nil {
		t.Fatal(err)
	}
	rule := chain.NewRule()
	rule.SetL4Proto(RuleL4Tcp)
	rule.SetL4Set("setportrange", RuleDireDst)
	rule.SetAccept()

	err = chain.AddRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	err = chain.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddRuleCtState(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := tbl.GetChainByName("mychain")
	if err != nil {
		t.Fatal(err)
	}
	rule := chain.NewRule()
	rule.SetCt(RuleCtEstablished, RuleCtRelated)
	rule.SetAccept()

	err = chain.AddRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	err = chain.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestListRule(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := tbl.GetChainByName("mychain")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := chain.ListRule()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(IndentJson(rules))
}

func TestTemp(t *testing.T) {
	t.Log(6 & 1)
}
