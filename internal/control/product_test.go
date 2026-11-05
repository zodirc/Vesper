package control

import (
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/identity"
)

func TestProductIdentityStoresCPEAndPURL(t *testing.T) {
	svc, err := New(t.TempDir(), func() time.Time { return time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	product, err := svc.AddProductIdentity(Product{
		Ecosystem: "PyPI", ProductName: "requests", CanonicalKey: "pypi:requests", Vendor: "Python Software Foundation",
		CPE23: "cpe:2.3:a:python:requests:*:*:*:*:*:*:*:*", PURL: "pkg:pypi/requests",
	}, []identity.Alias{
		{AliasType: "package_name", Value: "requests"},
		{AliasType: "cpe", Value: "cpe:2.3:a:Python:requests:*:*:*:*:*:*:*:*"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if product.Ecosystem != "pypi" || product.CPE23 != "cpe:2.3:a:python:requests:*:*:*:*:*:*:*:*" || svc.aliases[len(svc.aliases)-1].Value != product.CPE23 {
		t.Fatalf("product = %+v", product)
	}
	if _, err := svc.AddProduct("pypi", "requests", "pypi:requests", "Requests"); err == nil {
		t.Fatal("duplicate canonical key was accepted")
	}
	if _, err := svc.AddProductIdentity(Product{Ecosystem: "pypi", ProductName: "bad", CanonicalKey: "pypi:bad", CPE23: "cpe:2.3:a:only"}, nil); err == nil {
		t.Fatal("short cpe was accepted")
	}
}
