// Package forensic's integrity half: periodic seals over the log.
//
// The signed compliance report proves the DOCUMENT was not altered after it was
// produced. It says nothing about the log the document was computed from, and
// that log is an ordinary table an operator can DELETE from — the retention
// sweep does exactly that on a schedule. An auditor's first question is "what
// stops you removing the inconvenient rows before you generate the report", and
// until now the honest answer was "nothing".
//
// A seal answers it for a PERIOD rather than for a row: every entry in the
// period is hashed into a Merkle root, the root is recorded with the entry
// count, and each seal carries the previous seal's root. Removing an entry
// afterwards changes the root that recomputes from the surviving rows, and it
// no longer matches what was sealed. Rewriting the seal to match means
// rewriting every seal after it, because each one commits to its predecessor.
//
// WHAT THIS DOES NOT DO, stated here rather than discovered later:
//
//   - It does not make deletion impossible. It makes deletion DETECTABLE.
//   - A seal proves a period, not a row: an auditor learns that the period was
//     altered, not which entry is missing. Recovering the entry is impossible —
//     a root is not a backup.
//   - The seal is signed with the operator's own key, so an operator holding
//     that key can forge a consistent chain. What defeats that is anchoring a
//     root outside the operator's control — a timestamp authority, a public
//     log, an email to the auditor. THERE IS NO SUCH ANCHOR IN THIS CODE. An
//     earlier version of this comment named an AnchorRoot function as if one
//     existed; it never did, and the sentence survived long enough to be read
//     as a capability. Anchoring is an open item, not a shipped feature.
//   - An operator who deletes the chain head along with every seal leaves a
//     state indistinguishable from "seals were never enabled". The head makes
//     truncation visible while it is there; nothing inside one database can
//     make its own absence suspicious.
//
// The last two points matter most: without an external anchor this raises the
// cost of tampering from "one DELETE" to "rewrite the chain, move the head and
// re-sign both", which is a real improvement and not the same as proof.
package forensic

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// entryDigest is the hash of one forensic row.
//
// Length-prefixed, for the same reason the identity payload is: the fields are
// operator- and attacker-influenced text, and joining them with a delimiter
// lets two different rows produce one digest. `ip="1.2.3.4|GET"` with an empty
// method would collide with `ip="1.2.3.4"`, method `GET` — and an attacker who
// can pick a path can pick where a boundary falls.
func entryDigest(id int64, ts time.Time, tenant, ip, path, method, reason string, code int) []byte {
	h := sha256.New()
	write := func(s string) {
		_, _ = h.Write([]byte(strconv.Itoa(len(s))))
		_, _ = h.Write([]byte(":"))
		_, _ = h.Write([]byte(s))
	}
	write(strconv.FormatInt(id, 10))
	// UTC and RFC3339Nano so a seal recomputed in another session's timezone
	// produces the same bytes.
	write(ts.UTC().Format(time.RFC3339Nano))
	write(tenant)
	write(ip)
	write(path)
	write(method)
	write(strconv.Itoa(code))
	write(reason)
	sum := h.Sum(nil)
	return sum
}

// merkleRoot folds per-entry digests into one root.
//
// Ordinary binary Merkle tree, with the one detail that matters for an
// implementation someone else has to verify: an odd node at any level is
// PROMOTED unchanged rather than duplicated. Duplicating it is the classic
// CVE-2012-2459 shape, where two different trees produce the same root.
//
// The caller must pass digests in a fixed order (by id); order is part of what
// is committed to.
func merkleRoot(digests [][]byte) string {
	if len(digests) == 0 {
		// An empty period still gets a seal — "nothing happened here" is a
		// claim worth committing to, and its absence is otherwise
		// indistinguishable from a seal that was deleted.
		empty := sha256.Sum256(nil)
		return hex.EncodeToString(empty[:])
	}
	level := digests
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i]) // promote, never duplicate
				continue
			}
			h := sha256.New()
			_, _ = h.Write(level[i])
			_, _ = h.Write(level[i+1])
			next = append(next, h.Sum(nil))
		}
		level = next
	}
	return hex.EncodeToString(level[0])
}

// sealPayload is the exact byte string a seal's signature covers.
//
// prevRoot is inside it, which is what makes the chain a chain: re-sealing one
// period with different contents invalidates every seal after it unless those
// are re-signed too.
func sealPayload(tenant string, from, to time.Time, count int64, root, prevRoot string) []byte {
	return []byte(fmt.Sprintf("aegis-forensic-seal-v1\n%s\n%s\n%s\n%d\n%s\n%s",
		tenant,
		from.UTC().Format(time.RFC3339Nano),
		to.UTC().Format(time.RFC3339Nano),
		count,
		root,
		prevRoot,
	))
}

// headPayload is what a chain head's signature covers.
//
// The head is the anchor of the whole count, so it is the thing most worth
// forging: it states how many seals should exist and what the last root was.
// Signing it means moving the head backwards — the exact shape of a truncation
// — costs the signing key, where before it cost one DELETE.
//
// Deliberately a SEPARATE payload from sealPayload, not a bump of it. Making
// the seal payload carry seq would invalidate every seal already issued and
// force verifiers to understand two versions, and it would buy nothing: what
// detects a missing tail is the head's commitment to the count, not a number
// inside each link. The v1 seal format is therefore unchanged.
func headPayload(tenant string, seq int64, lastRoot string, lastEnd time.Time) []byte {
	return []byte(fmt.Sprintf("aegis-forensic-head-v1\n%s\n%d\n%s\n%s",
		tenant, seq, lastRoot, lastEnd.UTC().Format(time.RFC3339Nano)))
}
