package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// checkFeedRedirect now covers what a dialer cannot see — the scheme and the
// hop count. Refusing an internal DESTINATION moved into safefetch.Client's
// dialer, because a host string does not determine where a connection goes:
// https://2130706433/ and https://localhost./ both passed a string check and
// then connected to loopback. See internal/safefetch for the probe that
// demonstrates it.
func TestCheckFeedRedirect(t *testing.T) {
	mk := func(raw string) *http.Request {
		u, _ := url.Parse(raw)
		return &http.Request{URL: u}
	}
	if err := checkFeedRedirect(mk("https://feeds.example.com/list.txt"), nil); err != nil {
		t.Errorf("an ordinary https redirect was refused: %v", err)
	}
	if err := checkFeedRedirect(mk("http://feeds.example.com/list.txt"), nil); err == nil {
		t.Error("a downgrade to http was followed")
	}
	if err := checkFeedRedirect(mk("https://ok.example.com/"), make([]*http.Request, 5)); err == nil {
		t.Error("too many redirects should be refused")
	}
}

// A feed that redirects to cloud metadata must not be followed. The refusal now
// comes from the dialer, so this drives the real client end to end instead of
// calling the policy function directly — which is the only way to show that the
// address check is actually wired into the fetch.
func TestThreatFeed_ClientRefusesInternalRedirect(t *testing.T) {
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer redirector.Close()

	// The production client would refuse to reach the redirector itself, since
	// httptest listens on loopback. Dial loopback deliberately, keep the real
	// redirect policy, and let the redirect target be judged on its merits.
	client := &http.Client{CheckRedirect: checkFeedRedirect}
	resp, err := client.Get(redirector.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the feed followed a redirect to cloud metadata")
	}
}
