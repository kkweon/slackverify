package slackverify

import (
	"fmt"
	"testing"
)

func TestVerifyWithoutVersionNumber(t *testing.T) {
	slackSigningToken := []byte("8f742231b10e8888abcd99yyyzzz85a5")
	body := []byte("token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c")
	var timestamp int64 = 1531420618

	expectedHex := []byte("a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503")

	if ok := Verify(slackSigningToken, body, timestamp, expectedHex); !ok {
		t.Fatal("Failed to verify")
	}
}

func TestVerifyFail(t *testing.T) {
	slackSigningToken := []byte("8f742231b10e8888abcd99yyyzzz85a5")
	body := []byte("token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c")
	var timestamp int64 = 1531420618

	expectedHex := []byte("this should fail")

	if ok := Verify(slackSigningToken, body, timestamp, expectedHex); ok {
		t.Fatal("This should not be verified")
	}
}

func ExampleVerify() {
	// Slack Official Documentation Example
	slackSigningToken := []byte("8f742231b10e8888abcd99yyyzzz85a5")
	body := []byte("token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c")
	timestamp := int64(1531420618)

	expectedHex := []byte("v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503")

	ok := Verify(slackSigningToken, body, timestamp, expectedHex)
	fmt.Println(ok)
	// Output: true
}
