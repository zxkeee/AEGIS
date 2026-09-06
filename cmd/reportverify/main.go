// Command reportverify generates the AEGIS report signing key and verifies the
// reports signed with it.
//
// It exists because "the report is signed" is worth nothing to the person who
// receives it unless they can check it without writing code. This is the tool
// an operator hands to their auditor alongside the report: a single static
// binary that needs no gateway, no database and no network.
//
//	reportverify -genkey
//	reportverify -in report.json -key-id 3f2a...
//	reportverify -in report.json -pubkey <base64>
//
// Exit status is 0 only if the report verifies against the key the caller
// pinned. Everything else is 1.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"api-gateway/internal/attest"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "reportverify:", err)
		os.Exit(1)
	}
}

func run() error {
	genKey := flag.Bool("genkey", false, "generate a new report signing key and exit")
	in := flag.String("in", "", "path to a signed report ('-' for stdin)")
	keyID := flag.String("key-id", "", "the key id you expect to have signed it")
	pubKey := flag.String("pubkey", "", "the base64 public key you expect to have signed it")
	quiet := flag.Bool("quiet", false, "print nothing; report the result in the exit status")
	flag.Parse()

	if *genKey {
		return generate()
	}
	if *in == "" {
		flag.Usage()
		return fmt.Errorf("nothing to do: pass -in <report> or -genkey")
	}
	return verify(*in, *keyID, *pubKey, *quiet)
}

func generate() error {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	signer, err := attest.NewSigner(base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		return fmt.Errorf("the generated key was rejected: %w", err)
	}
	fmt.Println("# Set this on the gateway. It is a secret: it signs audit evidence.")
	fmt.Println("# It must NOT be reused as the license key or any other secret.")
	fmt.Printf("AEGIS_REPORT_SIGNING_KEY=%s\n\n", base64.StdEncoding.EncodeToString(priv))
	fmt.Println("# Publish these two. An auditor pins the key id and checks reports against it.")
	fmt.Printf("key_id:     %s\n", signer.KeyID())
	fmt.Printf("public_key: %s\n", base64.StdEncoding.EncodeToString(pub))
	return nil
}

func verify(path, keyID, pubKey string, quiet bool) error {
	// Refusing here is the point of the tool.
	//
	// A signed report carries the public key that signed it, so it is always
	// possible to check a report against itself — and that check proves nothing:
	// anyone can edit the numbers, re-sign with a key they made up, and produce a
	// document that passes. The signature only means something once it is checked
	// against a key the reader got from somewhere else. So the tool will not run
	// without one.
	if keyID == "" && pubKey == "" {
		return fmt.Errorf("pass -key-id or -pubkey: a report checked only against the key it " +
			"carries proves nothing, because a forger supplies both. Get the key id from the " +
			"operator (GET /api/report/signing-key), not from the report")
	}

	raw, err := readInput(path)
	if err != nil {
		return err
	}
	var env attest.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("%s is not a signed report: %w", path, err)
	}
	if env.Attestation.Signature == "" {
		return fmt.Errorf("%s carries no attestation; it was fetched without ?sign=1", path)
	}

	pub, err := resolveKey(env, keyID, pubKey)
	if err != nil {
		return err
	}
	if err := attest.Verify(env, pub); err != nil {
		return err
	}
	if !quiet {
		fmt.Printf("OK  signed by %s at %s\n", env.Attestation.KeyID, env.Attestation.SignedAt)
		fmt.Printf("    %s\n", env.Attestation.Digest)
	}
	return nil
}

// resolveKey turns what the caller pinned into the key to verify against.
//
// An explicit -pubkey is used as given. A -key-id alone is enough on its own:
// the id is a hash of the public key, so an id the caller trusts authenticates
// the key travelling in the document — a forger cannot produce a different key
// with the same id.
func resolveKey(env attest.Envelope, keyID, pubKey string) (ed25519.PublicKey, error) {
	src := pubKey
	if src == "" {
		src = env.Attestation.PublicKey
	}
	raw, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return nil, fmt.Errorf("public key is not valid base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	pub := ed25519.PublicKey(raw)

	if keyID != "" && keyID != attest.KeyIDOf(pub) {
		return nil, fmt.Errorf("this report was signed by key %s, not the %s you pinned",
			attest.KeyIDOf(pub), keyID)
	}
	return pub, nil
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	b, err := os.ReadFile(path) // #nosec G304 -- the report to check is exactly what the caller names; that is the tool
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return b, nil
}
