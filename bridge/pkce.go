package bridge

import (
	"crypto/sha256"
	"encoding/base64"
)

func pkceHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
