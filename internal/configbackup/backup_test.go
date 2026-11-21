package configbackup

import (
	"bytes"
	"context"
	"github.com/GoreeCloud/DNS/internal/policy"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func syntheticFiles(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.txt")
	local := filepath.Join(dir, "local-records.txt")
	if err := os.WriteFile(rules, []byte("blocked.example\n@@||allowed.example^\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, []byte("A home.example 192.0.2.42\nAAAA home.example 2001:db8::42\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return rules, local
}

func TestRecoveryEnvelopeValidationAndScope(t *testing.T) {
	rules, local := syntheticFiles(t)
	rulesBytes, _ := os.ReadFile(rules)
	localBytes, _ := os.ReadFile(local)
	good := bundle{Format: bundleVersion, Rules: rulesBytes, LocalRecords: localBytes, RulesSHA256: hash(rulesBytes), RecordsSHA256: hash(localBytes)}
	if err := validate(good); err != nil {
		t.Fatal(err)
	}
	wrongVersion := good
	wrongVersion.Format = "legacy"
	if validate(wrongVersion) == nil {
		t.Fatal("accepted legacy bundle")
	}
	wrongChecksum := good
	wrongChecksum.RulesSHA256 = strings.Repeat("0", 64)
	if validate(wrongChecksum) == nil {
		t.Fatal("accepted corrupted checksum")
	}
	badPolicy := good
	badPolicy.Rules = []byte("bad ^ policy\n")
	badPolicy.RulesSHA256 = hash(badPolicy.Rules)
	if validate(badPolicy) == nil {
		t.Fatal("accepted bad policy")
	}
	badRecord := good
	badRecord.LocalRecords = []byte("A home.example not-an-address\n")
	badRecord.RecordsSHA256 = hash(badRecord.LocalRecords)
	if validate(badRecord) == nil {
		t.Fatal("accepted invalid address")
	}
	if err := os.Symlink(rules, filepath.Join(t.TempDir(), "symlink-rules.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := regularInput(filepath.Join(t.TempDir(), "missing"), 10); err == nil {
		t.Fatal("missing rules accepted")
	}
	symlink := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(rules, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := regularInput(symlink, policy.MaxFileBytes); err == nil {
		t.Fatal("symlinked input accepted")
	}
}

func TestEncryptedRecoveryRoundtripWithRealAge(t *testing.T) {
	if _, err := exec.LookPath("age"); err != nil {
		t.Skip("external age CLI unavailable; Ubuntu CI installs it for real encryption acceptance")
	}
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen unavailable")
	}
	ctx := context.Background()
	rules, local := syntheticFiles(t)
	base := t.TempDir()
	identity := filepath.Join(base, "private-age-identity")
	gen := exec.Command("age-keygen", "-o", identity)
	gen.Stdout = nil
	gen.Stderr = nil // never print the synthetic private identity
	if err := gen.Run(); err != nil {
		t.Fatalf("age key generation failed: %v", err)
	}
	if err := os.Chmod(identity, 0600); err != nil {
		t.Fatal(err)
	}
	rec, err := exec.Command("age-keygen", "-y", identity).Output()
	if err != nil {
		t.Fatal("age public recipient derivation failed")
	}
	recipient := strings.TrimSpace(string(rec))
	archive := filepath.Join(base, "configuration.age")
	if err := Backup(ctx, rules, local, recipient, archive); err != nil {
		t.Fatal(err)
	}
	cipher, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(cipher, []byte("age-encryption.org/v1\n")) {
		t.Fatal("archive was not age encrypted")
	}
	if bytes.Contains(cipher, []byte("blocked.example")) {
		t.Fatal("backup exposed private rule text")
	}
	st, err := os.Lstat(archive)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("encrypted backup permissions are not owner-only")
	}
	if err := Backup(ctx, rules, local, recipient, archive); err == nil {
		t.Fatal("backup overwrote an existing archive")
	}
	if err := Verify(ctx, archive, identity); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "restored-policy")
	if err := Restore(ctx, archive, identity, target, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("dry-run restore created a directory")
	}
	if err := Restore(ctx, archive, identity, target, true); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Lstat(target)
	if err != nil || dir.Mode().Perm() != 0700 {
		t.Fatal("staging directory permissions are not owner-only")
	}
	for _, entry := range []struct {
		name   string
		source string
	}{
		{"rules.txt", rules}, {"local-records.txt", local},
	} {
		source, _ := os.ReadFile(entry.source)
		restoredPath := filepath.Join(target, entry.name)
		restored, err := os.ReadFile(restoredPath)
		if err != nil || !bytes.Equal(restored, source) {
			t.Fatalf("restore altered %s", entry.name)
		}
		st, err := os.Lstat(restoredPath)
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatal("restored policy was not owner-only")
		}
	}
	if err := Restore(ctx, archive, identity, target, true); err == nil {
		t.Fatal("restore overwrote an existing directory")
	}
	if err := os.Chmod(identity, 0644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(ctx, archive, identity); err == nil {
		t.Fatal("world-readable age identity accepted")
	}
	if err := os.Chmod(identity, 0600); err != nil {
		t.Fatal(err)
	}
	// Corrupt in-place only in this disposable test fixture.
	corrupted := append([]byte(nil), cipher...)
	corrupted[len(corrupted)/2] ^= 0xff
	if err := os.WriteFile(filepath.Join(base, "tampered.age"), corrupted, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(ctx, filepath.Join(base, "tampered.age"), identity); err == nil {
		t.Fatal("modified ciphertext passed authenticity validation")
	}
}

func TestExclusiveEncryptedOutputAndSymlinkParent(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "exists.age")
	if err := os.WriteFile(existing, []byte("do-not-replace"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeEncryptedExclusive(existing, []byte("encrypted")); err == nil {
		t.Fatal("existing backup overwritten")
	}
	contents, _ := os.ReadFile(existing)
	if string(contents) != "do-not-replace" {
		t.Fatal("existing backup modified")
	}
	root := t.TempDir()
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if err := writeEncryptedExclusive(filepath.Join(alias, "test.age"), []byte("encrypted")); err == nil {
		t.Fatal("symlinked output directory accepted")
	}
}
