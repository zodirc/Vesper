package evidence

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPutReadAndReconcile(t *testing.T) {
	root := t.TempDir()
	store := Store{Root: root}
	object, err := store.Put(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC), []byte("banner"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.IsAbs(object.StorageKey) {
		t.Fatalf("storage key is absolute: %s", object.StorageKey)
	}
	got, err := store.Read(object.StorageKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "banner" {
		t.Fatalf("content = %q", got)
	}
	orphans, missing, mismatch, err := store.Reconcile(map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if len(orphans) != 1 || len(missing) != 0 || len(mismatch) != 0 {
		t.Fatalf("orphans=%v missing=%v mismatch=%v", orphans, missing, mismatch)
	}
	if _, err := store.Read("../" + object.StorageKey); err == nil {
		t.Fatal("path escape was accepted")
	}
	digestPath := filepath.Join(root, filepath.FromSlash(object.StorageKey)+".sha256")
	if err := os.WriteFile(digestPath, []byte("00\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(object.StorageKey); err == nil {
		t.Fatal("digest mismatch was accepted")
	}
}
