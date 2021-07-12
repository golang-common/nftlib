// +build linux

package nftlib

import (
	"fmt"
	"github.com/stretchr/testify/suite"
	"testing"
)

type NftTest struct {
	suite.Suite
	table *Table
	chain *Chain
	rule  *Rule
	set   *Set
}

func (d *NftTest) SetupSuite() {
	fmt.Println("测试开始")
}

func (d *NftTest) TearDownSuite() {
	fmt.Println("测试结束")
}

func (d *NftTest) Test01_AddTable() {
	conn, err := New()
	if err != nil {
		panic(err)
	}
	table, err := conn.ADDTable("mytable", TableFamilyInet)
	if err != nil {
		panic(err)
	}
	d.table = table
	fmt.Println("创建mytable表成功")
}

func (d *NftTest) Test02_AddChain() {
	chain, err := d.table.AddBaseChain("mychain", ChainTypeFilter, ChainHookInput, ChainPolicyAccept)
	if err != nil {
		panic(err)
	}
	d.chain = chain
	fmt.Println("创建mychain链成功")
}

func (d *NftTest) Test03_AddSetIpv4() {
	set, err := d.table.AddSet("set1", SetDtypeIpv4, true, "192.168.1.5", "10.0.0.100-10.0.0.200", "172.16.0.0/16")
	if err != nil {
		panic(err)
	}
	fmt.Println(IndentJson(set))
	d.set = set
	fmt.Println("创建ipv4类型集合set1成功")
}

func (d *NftTest) Test04_AddRuleWithSet() {
	rule := d.chain.NewRule()
	rule.SetL3IpSet(d.set.Name, RuleDireSrc)
	rule.SetAccept()
	err := d.chain.AddRule(rule)
	if err != nil {
		panic(err)
	}
	err = d.chain.Commit()
	if err != nil {
		panic(err)
	}
}

func TestNft(t *testing.T) {
	suite.Run(t, new(NftTest))
}
