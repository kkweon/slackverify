package slackverify

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Verify verifies Slack Request
func Verify(token []byte, body []byte, timestamp int64, expectedHex []byte) bool {
	sigBaseString := []byte(fmt.Sprintf("v0:%v:%v", timestamp, string(body)))

	mac := hmac.New(sha256.New, token)
	_, err := mac.Write(sigBaseString)
	if err != nil {
		return false
	}
	code := mac.Sum(nil)

	expectedHex = bytes.Replace(expectedHex, []byte("v0="), []byte(""), 1)
	expected := make([]byte, hex.DecodedLen(len(expectedHex)))

	_, err = hex.Decode(expected, expectedHex)

	if err != nil {
		return false
	}

	return hmac.Equal(code, expected)
}
