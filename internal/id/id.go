// Package id 提供跨模块引用使用的 UUID。
// Package id provides UUIDs used as cross-module references.
package id

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// ID 是 RFC 4122 形式的 16 字节标识，文本表现为 8-4-4-4-12。
// ID is a 16-byte RFC 4122 identifier rendered as 8-4-4-4-12 text.
type ID [16]byte

// New 生成第 4 版随机标识。
// New generates a version-4 random identifier.
//
// 随机源失败时返回错误，不返回零值冒充有效标识。
// It returns an error when the random source fails and does not substitute the zero value.
func New() (ID, error) {
	var id ID
	if _, err := rand.Read(id[:]); err != nil {
		return ID{}, fmt.Errorf("generate id: %w", err)
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id, nil
}

// MustNew 生成标识，随机源失败时中止进程。
// MustNew generates an identifier and aborts the process when the random source fails.
func MustNew() ID {
	id, err := New()
	if err != nil {
		panic(err)
	}
	return id
}

// Parse 解析标准文本形式的标识。
// Parse parses the canonical textual form.
func Parse(text string) (ID, error) {
	if len(text) != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-' {
		return ID{}, fmt.Errorf("parse id %q: invalid format", text)
	}
	raw := text[0:8] + text[9:13] + text[14:18] + text[19:23] + text[24:36]
	buf, err := hex.DecodeString(raw)
	if err != nil || len(buf) != 16 {
		return ID{}, fmt.Errorf("parse id %q: %w", text, err)
	}
	var id ID
	copy(id[:], buf)
	return id, nil
}

// String 返回标准文本形式。
// String returns the canonical textual form.
func (id ID) String() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
}

// IsZero 报告标识是否为全零。
// IsZero reports whether the identifier is all zeros.
func (id ID) IsZero() bool {
	return id == ID{}
}

// MarshalText 按标准文本编码。
// MarshalText encodes the canonical text.
func (id ID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText 按标准文本解码。
// UnmarshalText decodes the canonical text.
func (id *ID) UnmarshalText(text []byte) error {
	parsed, err := Parse(string(text))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}
