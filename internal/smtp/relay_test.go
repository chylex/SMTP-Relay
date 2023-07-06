package smtp

import (
	"testing"
)

func TestAddrAllowedNoDomain(t *testing.T) {
	allowedAddrs := []string{"joe@abc.com"}
	if addressAllowedByTemplate(allowedAddrs, "bob.com") {
		t.FailNow()
	}
}

func TestAddrAllowedSingle(t *testing.T) {
	allowedAddrs := []string{"joe@abc.com"}

	if !addressAllowedByTemplate(allowedAddrs, "joe@abc.com") {
		t.FailNow()
	}
	if addressAllowedByTemplate(allowedAddrs, "bob@abc.com") {
		t.FailNow()
	}
}

func TestAddrAllowedDifferentCase(t *testing.T) {
	allowedAddrs := []string{"joe@abc.com"}
	testAddrs := []string{
		"joe@ABC.com",
		"Joe@abc.com",
		"JOE@abc.com",
		"JOE@ABC.COM",
	}
	for _, addr := range testAddrs {
		if !addressAllowedByTemplate(allowedAddrs, addr) {
			t.Errorf("Address %v not allowed, but should be", addr)
		}
	}
}

func TestAddrAllowedLocal(t *testing.T) {
	allowedAddrs := []string{"joe"}

	if !addressAllowedByTemplate(allowedAddrs, "joe") {
		t.FailNow()
	}
	if addressAllowedByTemplate(allowedAddrs, "bob") {
		t.FailNow()
	}
}

func TestAddrAllowedMulti(t *testing.T) {
	allowedAddrs := []string{"joe@abc.com", "bob@def.com"}
	if !addressAllowedByTemplate(allowedAddrs, "joe@abc.com") {
		t.FailNow()
	}
	if !addressAllowedByTemplate(allowedAddrs, "bob@def.com") {
		t.FailNow()
	}
	if addressAllowedByTemplate(allowedAddrs, "bob@abc.com") {
		t.FailNow()
	}
}

func TestAddrAllowedSingleDomain(t *testing.T) {
	allowedAddrs := []string{"@abc.com"}
	if !addressAllowedByTemplate(allowedAddrs, "joe@abc.com") {
		t.FailNow()
	}
	if addressAllowedByTemplate(allowedAddrs, "joe@def.com") {
		t.FailNow()
	}
}

func TestAddrAllowedMixed(t *testing.T) {
	allowedAddrs := []string{"app", "app@example.com", "@appsrv.example.com"}
	if !addressAllowedByTemplate(allowedAddrs, "app") {
		t.FailNow()
	}
	if !addressAllowedByTemplate(allowedAddrs, "app@example.com") {
		t.FailNow()
	}
	if addressAllowedByTemplate(allowedAddrs, "ceo@example.com") {
		t.FailNow()
	}
	if !addressAllowedByTemplate(allowedAddrs, "root@appsrv.example.com") {
		t.FailNow()
	}
	if !addressAllowedByTemplate(allowedAddrs, "dev@appsrv.example.com") {
		t.FailNow()
	}
	if addressAllowedByTemplate(allowedAddrs, "appsrv@example.com") {
		t.FailNow()
	}
}
