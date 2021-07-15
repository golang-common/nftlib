// +build linux

package nftlib

import "testing"

func TestFlushRuleSet(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	conn.ClearAll()
	err = conn.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddSetIpv4(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	_, err = tbl.AddSet("setipv4", SetDtypeIpv4, false, "192.168.1.1", "192.168.1.2", "192.169.1.3")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(`add set "setipv4" success`)
}

func TestAddSetElemIpv4(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	set, err := tbl.GetSetByName("setipv4")
	if err != nil {
		t.Fatal(err)
	}
	err = set.AddElements("1.1.1.1", "1.1.1.2")
	if err != nil {
		t.Fatal(err)
	}
	err = set.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDelSetElemIpv4(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	set, err := tbl.GetSetByName("setipv4")
	if err != nil {
		t.Fatal(err)
	}
	err = set.DelElements("1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	err = set.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddSetIpv6(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	_, err = tbl.AddSet("setipv6", SetDtypeIpv6, false, "ffee::1", "ffee::3", "ffee::5")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(`add set "setipv4" success`)
}

func TestAddSetElemIpv6(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	set, err := tbl.GetSetByName("setipv6")
	if err != nil {
		t.Fatal(err)
	}
	err = set.AddElements("ffee::7", "ffee::9")
	if err != nil {
		t.Fatal(err)
	}
	err = set.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDelSetElemIpv6(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	set, err := tbl.GetSetByName("setipv6")
	if err != nil {
		t.Fatal(err)
	}
	err = set.DelElements("ffee::7")
	if err != nil {
		t.Fatal(err)
	}
	err = set.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddSetIpv4Range(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	_, err = tbl.AddSet("setipv4range", SetDtypeIpv4, true, "192.168.1.0/24", "192.168.2.0-192.168.2.100", "192.168.3.0")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(`add set "setipv4range" success`)
}

func TestAddSetElemIpv4Range(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	set, err := tbl.GetSetByName("setipv4range")
	if err != nil {
		t.Fatal(err)
	}
	err = set.AddElements("192.168.2.101")
	if err != nil {
		t.Fatal(err)
	}
	err = set.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDelSetElemIpv4Range(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	set, err := tbl.GetSetByName("setipv4range")
	if err != nil {
		t.Fatal(err)
	}
	err = set.DelElements("192.168.3.0")
	if err != nil {
		t.Fatal(err)
	}
	err = set.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddSetIpv6Range(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	_, err = tbl.AddSet("setipv6range", SetDtypeIpv6, true, "ff01::-ff01:efef::", "ff02::/64", "ffdd::f")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(`add set "setipv6range" success`)
}

func TestAddSetElemIpv6Range(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	set, err := tbl.GetSetByName("setipv6range")
	if err != nil {
		t.Fatal(err)
	}
	err = set.AddElements("ff03::/65", "ff04::-ff05::", "ff06::f")
	if err != nil {
		t.Fatal(err)
	}
	err = set.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDelSetElemIpv6Range(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	set, err := tbl.GetSetByName("setipv6range")
	if err != nil {
		t.Fatal(err)
	}
	err = set.DelElements("ff06::f")
	if err != nil {
		t.Fatal(err)
	}
	err = set.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddSetPort(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	_, err = tbl.AddSet("setport", SetDtypePort, false, "3306", "3307", "80", "8080")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(`add set "setport" success`)
}

func TestAddElemSetPort(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	set, err := tbl.GetSetByName("setport")
	if err != nil {
		t.Fatal(err)
	}
	err = set.AddElements("9999", "8888")
	if err != nil {
		t.Fatal(err)
	}
	err = set.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDelElemSetPort(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	set, err := tbl.GetSetByName("setport")
	if err != nil {
		t.Fatal(err)
	}
	err = set.DelElements("9999")
	if err != nil {
		t.Fatal(err)
	}
	err = set.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddSetPortRange(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	_, err = tbl.AddSet("setportrange", SetDtypePort, true, "3306-3309", "8080-18080", "30001")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(`add set "setport" success`)
}

func TestAddSetElemPortRange(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	set, err := tbl.GetSetByName("setportrange")
	if err != nil {
		t.Fatal(err)
	}
	err = set.AddElements("30002-30200", "40000-40100")
	if err != nil {
		t.Fatal(err)
	}
	err = set.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDelSetElemPortRange(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	set, err := tbl.GetSetByName("setportrange")
	if err != nil {
		t.Fatal(err)
	}
	err = set.DelElements("30001", "40000-40100")
	if err != nil {
		t.Fatal(err)
	}
	err = set.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestListSet(t *testing.T) {
	conn, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := conn.GetTableByName("mytable")
	if err != nil {
		t.Fatal(err)
	}
	sets, err := tbl.ListSet()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(IndentJson(sets))
}
