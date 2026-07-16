package certinfo

import (
	"os"
	"path/filepath"
	"testing"
)

// buildCertTree fabricates a certmagic-shaped storage dir with the
// given (issuer, safeDomain) leaf dirs each holding a .crt/.key/.json.
func buildCertTree(t *testing.T, leaves map[string][]string) string {
	t.Helper()
	root := t.TempDir()
	for issuer, domains := range leaves {
		for _, d := range domains {
			dir := filepath.Join(root, "certificates", issuer, d)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatalf("mkdir %s: %v", dir, err)
			}
			for _, ext := range []string{".crt", ".key", ".json"} {
				if err := os.WriteFile(filepath.Join(dir, d+ext), []byte("x"), 0o600); err != nil {
					t.Fatalf("write: %v", err)
				}
			}
		}
	}
	return root
}

func TestDeleteCertFiles_RemovesAcrossIssuers(t *testing.T) {
	root := buildCertTree(t, map[string][]string{
		"acme-v02.api.letsencrypt.org-directory": {"darro.ovh"},
		"local":                                  {"darro.ovh"},
	})
	n, err := DeleteCertFiles(root, "darro.ovh")
	if err != nil {
		t.Fatalf("DeleteCertFiles: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d; want 2 (both issuers)", n)
	}
	for _, issuer := range []string{"acme-v02.api.letsencrypt.org-directory", "local"} {
		if _, err := os.Stat(filepath.Join(root, "certificates", issuer, "darro.ovh")); !os.IsNotExist(err) {
			t.Errorf("issuer %s domain dir still present", issuer)
		}
	}
}

func TestDeleteCertFiles_Wildcard(t *testing.T) {
	// *.darro.ovh is stored under the certmagic-safe name
	// "wildcard_.darro.ovh".
	root := buildCertTree(t, map[string][]string{
		"acme-v02.api.letsencrypt.org-directory": {"wildcard_.darro.ovh"},
	})
	n, err := DeleteCertFiles(root, "*.darro.ovh")
	if err != nil {
		t.Fatalf("DeleteCertFiles: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted = %d; want 1 (wildcard)", n)
	}
	if _, err := os.Stat(filepath.Join(root, "certificates", "acme-v02.api.letsencrypt.org-directory", "wildcard_.darro.ovh")); !os.IsNotExist(err) {
		t.Error("wildcard dir still present")
	}
}

func TestDeleteCertFiles_Idempotent_Absent(t *testing.T) {
	root := buildCertTree(t, map[string][]string{
		"acme-v02.api.letsencrypt.org-directory": {"other.example.com"},
	})
	n, err := DeleteCertFiles(root, "notpresent.example.com")
	if err != nil {
		t.Fatalf("DeleteCertFiles: %v", err)
	}
	if n != 0 {
		t.Errorf("deleted = %d; want 0 (absent domain)", n)
	}
	// The unrelated domain is untouched.
	if _, err := os.Stat(filepath.Join(root, "certificates", "acme-v02.api.letsencrypt.org-directory", "other.example.com")); err != nil {
		t.Errorf("unrelated domain dir removed: %v", err)
	}
}

func TestDeleteCertFiles_NeverTouchesPKIorLocks(t *testing.T) {
	root := buildCertTree(t, map[string][]string{"local": {"darro.ovh"}})
	// Fabricate sibling pki/ and locks/ dirs that must survive.
	for _, sib := range []string{"pki", "locks"} {
		if err := os.MkdirAll(filepath.Join(root, sib), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", sib, err)
		}
	}
	if _, err := DeleteCertFiles(root, "darro.ovh"); err != nil {
		t.Fatalf("DeleteCertFiles: %v", err)
	}
	for _, sib := range []string{"pki", "locks"} {
		if _, err := os.Stat(filepath.Join(root, sib)); err != nil {
			t.Errorf("sibling %s removed: %v", sib, err)
		}
	}
}

func TestDeleteCertFiles_EmptyArgs(t *testing.T) {
	if _, err := DeleteCertFiles("", "darro.ovh"); err == nil {
		t.Error("want error for empty storageDir")
	}
	if _, err := DeleteCertFiles(t.TempDir(), ""); err == nil {
		t.Error("want error for empty domain")
	}
}
