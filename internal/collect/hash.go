package collect

import (
	"crypto/sha256"
	"encoding/hex"
)

func hashText(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}
