// Package evidence 把原始证据写入本地文件系统，并向调用方返回存储键和摘要。
// Package evidence writes raw evidence to the local filesystem and returns a storage key and digest to the caller.
//
// 存储键是相对对象键，不包含绝对路径。读取时拒绝路径逃逸。
// The storage key is a relative object key and does not contain an absolute path. Reads reject path escape.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zodirc/Vesper/internal/id"
)

// Object 是一次成功发布的证据对象。
// Object is an evidence object that was published successfully.
type Object struct {
	StorageKey      string
	SizeBytes       int64
	DigestAlgorithm string
	ContentDigest   string
}

// Store 是本地证据目录。
// Store is the local evidence directory.
type Store struct {
	Root string
}

// Put 按临时文件、摘要、同步、原子改名的顺序发布证据。
// Put publishes evidence in the order temporary file, digest, sync, and atomic rename.
//
// content 可以为空。now 用于生成日期前缀。失败时不返回可引用对象。
// content may be empty. now forms the date prefix. On failure it does not return a referenceable object.
func (s Store) Put(now time.Time, content []byte) (Object, error) {
	if s.Root == "" {
		return Object{}, fmt.Errorf("evidence root is empty")
	}
	objectID, err := id.New()
	if err != nil {
		return Object{}, err
	}
	key := filepath.ToSlash(filepath.Join(now.UTC().Format("2006/01/02"), objectID.String()))
	finalPath, err := s.resolve(key)
	if err != nil {
		return Object{}, err
	}
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o750); err != nil {
		return Object{}, fmt.Errorf("create evidence directory: %w", err)
	}
	tmpDir := filepath.Join(s.Root, ".tmp")
	if err := os.MkdirAll(tmpDir, 0o750); err != nil {
		return Object{}, fmt.Errorf("create evidence temp directory: %w", err)
	}
	tmp, err := os.CreateTemp(tmpDir, "evidence-*")
	if err != nil {
		return Object{}, fmt.Errorf("create evidence temp file: %w", err)
	}
	tmpName := tmp.Name()
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpName)
		}
	}()
	sum := sha256.New()
	writer := io.MultiWriter(tmp, sum)
	n, err := writer.Write(content)
	if err != nil {
		_ = tmp.Close()
		return Object{}, fmt.Errorf("write evidence temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return Object{}, fmt.Errorf("sync evidence temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return Object{}, fmt.Errorf("close evidence temp file: %w", err)
	}
	if err := os.Rename(tmpName, finalPath); err != nil {
		return Object{}, fmt.Errorf("publish evidence object: %w", err)
	}
	success = true
	if err := syncDir(filepath.Dir(finalPath)); err != nil {
		return Object{}, err
	}
	digest := hex.EncodeToString(sum.Sum(nil))
	if err := os.WriteFile(finalPath+".sha256", []byte(digest+"\n"), 0o640); err != nil {
		return Object{}, fmt.Errorf("write evidence digest: %w", err)
	}
	return Object{
		StorageKey: key, SizeBytes: int64(n), DigestAlgorithm: "sha256", ContentDigest: digest,
	}, nil
}

// Read 按存储键读取证据并核对旁路摘要。
// Read loads evidence by storage key and checks the sidecar digest.
//
// 摘要不一致时返回错误，不把内容当作有效证据。
// It returns an error when the digest does not match and does not treat the content as valid evidence.
func (s Store) Read(key string) ([]byte, error) {
	path, err := s.resolve(key)
	if err != nil {
		return nil, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read evidence %s: %w", key, err)
	}
	recorded, err := os.ReadFile(path + ".sha256")
	if err != nil {
		return nil, fmt.Errorf("read evidence digest %s: %w", key, err)
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != strings.TrimSpace(string(recorded)) {
		return nil, fmt.Errorf("evidence digest mismatch: %s", key)
	}
	return content, nil
}

// Reconcile 对比已知摘要，找出孤儿文件、缺失文件和摘要不一致。
// Reconcile compares known digests and reports orphan files, missing files, and digest mismatches.
//
// known 的键是存储键，值是期望的 SHA-256 十六进制摘要。
// The keys of known are storage keys and the values are expected SHA-256 hex digests.
func (s Store) Reconcile(known map[string]string) (orphans, missing, mismatch []string, err error) {
	if s.Root == "" {
		return nil, nil, nil, fmt.Errorf("evidence root is empty")
	}
	if _, statErr := os.Stat(s.Root); os.IsNotExist(statErr) {
		for key := range known {
			missing = append(missing, key)
		}
		return nil, missing, nil, nil
	}
	seen := map[string]struct{}{}
	err = filepath.WalkDir(s.Root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if strings.HasSuffix(entry.Name(), ".sha256") || strings.Contains(path, string(filepath.Separator)+".tmp"+string(filepath.Separator)) {
			return nil
		}
		rel, relErr := filepath.Rel(s.Root, path)
		if relErr != nil {
			return relErr
		}
		key := filepath.ToSlash(rel)
		seen[key] = struct{}{}
		expect, ok := known[key]
		if !ok {
			orphans = append(orphans, key)
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			mismatch = append(mismatch, key)
			return nil
		}
		sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) != expect {
			mismatch = append(mismatch, key)
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reconcile evidence: %w", err)
	}
	for key := range known {
		if _, ok := seen[key]; !ok {
			missing = append(missing, key)
		}
	}
	return orphans, missing, mismatch, nil
}

func (s Store) resolve(key string) (string, error) {
	if key == "" || strings.Contains(key, "..") || strings.HasPrefix(key, "/") {
		return "", fmt.Errorf("invalid evidence key %q", key)
	}
	clean := filepath.Clean(filepath.FromSlash(key))
	full := filepath.Join(s.Root, clean)
	root := filepath.Clean(s.Root) + string(filepath.Separator)
	if !strings.HasPrefix(full, root) && filepath.Clean(full) != filepath.Clean(s.Root) {
		return "", fmt.Errorf("evidence key escapes root: %s", key)
	}
	return full, nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open evidence directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync evidence directory: %w", err)
	}
	return nil
}
