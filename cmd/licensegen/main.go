// Command licensegen is the OFFLINE tool that issues AEGIS license files. It
// never runs inside a deployed gateway and its private key output must never
// be committed to this repository — see docs/licensing.md.
//
// Usage:
//
//	# once, keep aegis-license.key SECRET and offline:
//	go run ./cmd/licensegen -genkey -out aegis-license
//
//	# embed the printed public key into release builds via:
//	#   go build -ldflags "-X api-gateway/internal/license.publicKeyB64=<pub>" ./cmd/gateway
//
//	# have the customer report their machine's fingerprint (on THEIR box):
//	#   go run ./cmd/gateway -print-fingerprint
//
//	# issue a license for a customer, node-locked to that fingerprint:
//	go run ./cmd/licensegen -issue \
//	    -key aegis-license.key \
//	    -licensee "Acme Corp" \
//	    -tier pilot \
//	    -days 30 \
//	    -hardware-id <fingerprint the customer sent you> \
//	    -out acme-pilot.lic
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"api-gateway/internal/license"
)

func main() {
	genKey := flag.Bool("genkey", false, "generate a new Ed25519 keypair and exit")
	issue := flag.Bool("issue", false, "issue a signed license file")
	keyPath := flag.String("key", "", "path to the private key file (from -genkey)")
	out := flag.String("out", "", "output path (for -genkey: <out>.key/<out>.pub; for -issue: the license file)")
	licensee := flag.String("licensee", "", "who this license is issued to")
	tier := flag.String("tier", "trial", "trial | pilot | production")
	days := flag.Int("days", 30, "days until expiry (0 = never expires — internal/demo use only)")
	features := flag.String("features", "", "comma-separated feature flags, e.g. sso,multitenancy")
	maxRPS := flag.Int("max-rps", 0, "advisory max RPS the caller may enforce (0 = unlimited)")
	hardwareID := flag.String("hardware-id", "", "node-lock to this machine fingerprint (from `gateway -print-fingerprint` run on the customer's box); empty = floating/unrestricted, internal use only")
	flag.Parse()

	switch {
	case *genKey:
		runGenKey(*out)
	case *issue:
		runIssue(*keyPath, *out, *licensee, *tier, *days, *features, *maxRPS, *hardwareID)
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func runGenKey(out string) {
	if out == "" {
		out = "aegis-license"
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	must(err)

	keyPath := out + ".key"
	must(os.WriteFile(keyPath, priv, 0o600))

	pubB64 := base64.StdEncoding.EncodeToString(pub)
	fmt.Printf("Private key written to %s — keep this OFFLINE and out of git. Anyone who has it can\n", keyPath)
	fmt.Println("issue valid licenses for your product; there is no way to revoke that after the fact.")
	fmt.Println()
	fmt.Println("Public key (embed this in release builds, safe to keep in build scripts/CI secrets):")
	fmt.Println()
	fmt.Printf("  %s\n\n", pubB64)
	fmt.Println("Build a licensed release with:")
	fmt.Printf("  go build -ldflags \"-X api-gateway/internal/license.publicKeyB64=%s\" ./cmd/gateway\n", pubB64)
}

func runIssue(keyPath, out, licensee, tier string, days int, featuresCSV string, maxRPS int, hardwareID string) {
	if keyPath == "" || licensee == "" || out == "" {
		fmt.Fprintln(os.Stderr, "usage: licensegen -issue -key <priv.key> -licensee <name> -out <file.lic> "+
			"[-tier trial|pilot|production] [-days N] [-features a,b] [-max-rps N] [-hardware-id <fingerprint>]")
		os.Exit(2)
	}
	if hardwareID == "" {
		fmt.Fprintln(os.Stderr, "warning: no -hardware-id given — this license is NOT node-locked and will run "+
			"on any machine. Have the customer run `go run ./cmd/gateway -print-fingerprint` on the box that will "+
			"actually run the gateway and pass its output as -hardware-id, unless this is deliberately a floating "+
			"internal/demo license.")
	}
	raw, err := os.ReadFile(keyPath) // #nosec G304 -- operator-supplied path, offline tool
	must(err)
	if len(raw) != ed25519.PrivateKeySize {
		fmt.Fprintf(os.Stderr, "%s does not look like an Ed25519 private key (got %d bytes, want %d)\n", keyPath, len(raw), ed25519.PrivateKeySize)
		os.Exit(1)
	}
	priv := ed25519.PrivateKey(raw)

	var feats []string
	if featuresCSV != "" {
		for _, f := range strings.Split(featuresCSV, ",") {
			if f = strings.TrimSpace(f); f != "" {
				feats = append(feats, f)
			}
		}
	}

	c := license.Claims{
		Licensee:   licensee,
		Tier:       tier,
		IssuedAt:   time.Now().UTC(),
		Features:   feats,
		MaxRPS:     maxRPS,
		HardwareID: hardwareID,
	}
	if days > 0 {
		c.ExpiresAt = time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour)
	}

	signed, err := license.Sign(priv, c)
	must(err)
	must(os.WriteFile(out, []byte(signed), 0o644)) // #nosec G306,G703 -- operator-supplied -out path (offline CLI tool, not user input); license file is not secret material

	fmt.Printf("Issued %s license for %q → %s", tier, licensee, out)
	if days > 0 {
		fmt.Printf(" (expires %s)", c.ExpiresAt.Format("2006-01-02"))
	} else {
		fmt.Print(" (never expires)")
	}
	if hardwareID != "" {
		fmt.Printf(" [locked to %s]\n", hardwareID)
	} else {
		fmt.Println(" [NOT hardware-locked]")
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "licensegen: "+err.Error())
		os.Exit(1)
	}
}
