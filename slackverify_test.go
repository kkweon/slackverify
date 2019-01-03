package slackverify

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
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

func TestVerifyRequest(t *testing.T) {
	bodyRaw := "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c"
	body := bytes.NewBufferString(bodyRaw)
	req, _ := http.NewRequest("POST", "/api/doesn'tmatter", body)
	req.Header.Add("X-Slack-Request-Timestamp", "1531420618")
	req.Header.Add("X-Slack-Signature", "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503")
	slackSigningToken := []byte("8f742231b10e8888abcd99yyyzzz85a5")

	if !VerifyRequest(req, slackSigningToken) {
		t.Fatal("Failed to verify with the request object")
	}

	if b, err := ioutil.ReadAll(req.Body); err != nil || string(b) != bodyRaw {
		t.Fatal("It should not consume body")
	}
}

func TestFailVerifyRequest(t *testing.T) {
	type testCase struct {
		request *http.Request
	}
	testCases := make([]testCase, 0)

	// no timestamp
	req, _ := http.NewRequest("POST", "/api/doesn'tmatter", nil)
	testCases = append(testCases, testCase{req})

	// bad timestamp
	req, _ = http.NewRequest("POST", "/api/doesn'tmatter", nil)
	req.Header.Add("X-Slack-Request-Timestamp", "Not a timestamp")
	req.Header.Add("X-Slack-Signature", "slack-signature")
	testCases = append(testCases, testCase{req})

	for _, testCase := range testCases {
		if VerifyRequest(testCase.request, []byte("8f742231b10e8888abcd99yyyzzz85a5")) {
			t.Fatal("It should fail")
		}
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
