// Package configbackup provides recipient-encrypted, explicitly scoped,
// staging-only policy recovery. It never reads API tokens, TLS keys or logs.
package configbackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/GoreeCloud/DNS/internal/policy"
	"github.com/GoreeCloud/DNS/internal/records"
)

const (
	bundleVersion = "goreecloud-dns-config-v1"
	maxArchive    = policy.MaxFileBytes + records.MaxFileBytes + (1 << 20)
)

type bundle struct {
	Format        string `json:"format"`
	Rules         []byte `json:"rules"`
	LocalRecords  []byte `json:"local_records"`
	RulesSHA256   string `json:"rules_sha256"`
	RecordsSHA256 string `json:"records_sha256"`
}

func hash(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

func regularInput(path string, max int64) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > max {
		return nil, errors.New("source must be a bounded regular file, not a symlink")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errors.New("source exceeds size limit")
	}
	return data, nil
}

func validate(b bundle) error {
	if b.Format != bundleVersion || len(b.Rules) > policy.MaxFileBytes ||
		len(b.LocalRecords) > records.MaxFileBytes ||
		b.RulesSHA256 != hash(b.Rules) || b.RecordsSHA256 != hash(b.LocalRecords) {
		return errors.New("unsupported or corrupted configuration bundle")
	}
	if _, err := policy.Parse(bytes.NewReader(b.Rules)); err != nil {
		return errors.New("invalid DNS filter policy")
	}
	if _, err := records.Parse(bytes.NewReader(b.LocalRecords)); err != nil {
		return errors.New("invalid local DNS records")
	}
	return nil
}

type limitedWriter struct {
	bytes.Buffer
	max int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.Len()+len(p) > w.max {
		return 0, errors.New("age output exceeds configured limit")
	}
	return w.Buffer.Write(p)
}

func runAge(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	if _, err := exec.LookPath("age"); err != nil {
		return nil, errors.New("verified age CLI is required")
	}
	command := exec.CommandContext(ctx, "age", args...)
	command.Stdin = bytes.NewReader(input)
	cipher := &limitedWriter{max: maxArchive}
	command.Stdout = cipher
	command.Stderr = io.Discard // Never echo private DNS names, keys or recipient details.
	if err := command.Run(); err != nil {
		return nil, errors.New("age encryption/decryption failed")
	}
	return cipher.Bytes(), nil
}

// Backup validates both source files before encrypting the policy and local
// overrides to one age recipient. It never writes plaintext to an output file,
// never reads environment credentials and will not replace an existing archive.
func Backup(ctx context.Context, rulesFile, recordsFile, recipient, destination string) error {
	if !strings.HasPrefix(recipient, "age1") || len(recipient) < 40 || len(recipient) > 150 ||
		strings.ContainsAny(recipient, " \t\r\n") {
		return errors.New("use a verified age X25519 public recipient")
	}
	rules, err := regularInput(rulesFile, policy.MaxFileBytes)
	if err != nil {
		return fmt.Errorf("read rules: %w", err)
	}
	local, err := regularInput(recordsFile, records.MaxFileBytes)
	if err != nil {
		return fmt.Errorf("read local records: %w", err)
	}
	data := bundle{Format: bundleVersion, Rules: rules, LocalRecords: local,
		RulesSHA256: hash(rules), RecordsSHA256: hash(local)}
	if err := validate(data); err != nil {
		return err
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	encrypted, err := runAge(ctx, payload, "-r", recipient)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(encrypted, []byte("age-encryption.org/v1\n")) {
		return errors.New("encrypted output has no age format header")
	}
	return writeEncryptedExclusive(destination, encrypted)
}

func safeParent(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(abs)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	if filepath.Clean(resolved) != filepath.Clean(parent) {
		return "", errors.New("symlinked destination parents are not allowed")
	}
	st, err := os.Lstat(parent)
	if err != nil || !st.IsDir() {
		return "", errors.New("destination parent is not a directory")
	}
	return abs, nil
}

func writeEncryptedExclusive(destination string, encrypted []byte) error {
	dest, err := safeParent(destination)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".dns-age-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	_, err = tmp.Write(encrypted)
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	// Hard-link creation is atomic and fails if the target already exists.
	// os.Rename would silently overwrite a previously verified backup.
	return os.Link(tmp.Name(), dest)
}

// Verify decrypts in memory, validates checksums and runs the production
// policy and record parsers. It does not write decrypted material to disk.
func Verify(ctx context.Context, archive, identity string) error {
	_, err := decryptAndValidate(ctx, archive, identity)
	return err
}

func decryptAndValidate(ctx context.Context, archive, identity string) (bundle, error) {
	var empty bundle
	keyInfo, err := os.Lstat(identity)
	if err != nil {
		return empty, errors.New("age identity file is unavailable")
	}
	if !keyInfo.Mode().IsRegular() || keyInfo.Mode().Perm()&0077 != 0 {
		return empty, errors.New("age identity must be a regular owner-only file")
	}
	cipher, err := regularInput(archive, maxArchive)
	if err != nil {
		return empty, errors.New("encrypted archive is unavailable or oversized")
	}
	if !bytes.HasPrefix(cipher, []byte("age-encryption.org/v1\n")) {
		return empty, errors.New("expected an encrypted age file")
	}
	plain, err := runAge(ctx, cipher, "-d", "-i", identity)
	if err != nil {
		return empty, err
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	var data bundle
	if err := decoder.Decode(&data); err != nil {
		return empty, errors.New("invalid recovery envelope")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return empty, errors.New("trailing recovery data")
	}
	if err := validate(data); err != nil {
		return empty, err
	}
	return data, nil
}

// Restore only creates a NEW staging directory, never modifies an active
// service, its existing config files or system DNS. apply=false is a dry-run.
func Restore(ctx context.Context, archive, identity, target string, apply bool) error {
	data, err := decryptAndValidate(ctx, archive, identity)
	if err != nil {
		return err
	}
	if !apply {
		return nil
	}
	dir, err := safeParent(target)
	if err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("restore requires a new empty destination: %w", err)
	}
	created := []string{}
	defer func() {
		// On error, never recursively delete an operator's pre-existing data.
		// Only remove files created by this invocation in its new directory.
		if err != nil {
			for _, path := range created {
				_ = os.Remove(path)
			}
			_ = os.Remove(dir)
		}
	}()
	for _, entry := range []struct {
		name  string
		value []byte
	}{
		{"rules.txt", data.Rules}, {"local-records.txt", data.LocalRecords},
	} {
		path := filepath.Join(dir, entry.name)
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			err = e
			return err
		}
		created = append(created, path)
		_, e = f.Write(entry.value)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil {
			err = e
			return err
		}
		if closeErr != nil {
			err = closeErr
			return err
		}
	}
	return nil
}
