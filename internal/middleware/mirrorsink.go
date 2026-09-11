package middleware

import (
	"io"
	"net/http"
)

// MirrorSink is the innermost handler when the gateway receives mirrored
// traffic: it consumes the request and answers 204, forwarding nothing.
//
// It exists to make a first pilot acceptable. The objection that stops one is
// "I am not putting your process in front of my traffic", and it is a fair
// objection — an inline hop is a new way for someone else's production to
// break. With nginx's mirror directive (or Envoy shadow, or HAProxy) the
// customer's own gateway duplicates each request here and discards the reply,
// so their traffic never depends on this process at all.
//
// Two things this handler must get right:
//
//   - It must NOT forward. A mirrored request forwarded upstream would hit the
//     customer's backend a second time and replay every POST, turning a
//     read-only observation into a write. That is the whole risk the mirrored
//     deployment was chosen to avoid.
//   - It must drain the body. The middleware above may not have read it, and
//     leaving it unread makes the mirroring proxy's connection reuse fail and
//     shows up as errors on THEIR side.
//
// 204 rather than 200: there is no response to describe, and a body would be
// discarded by the mirroring proxy anyway.
func MirrorSink() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
