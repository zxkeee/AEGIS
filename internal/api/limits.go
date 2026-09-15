package api

// What a signed document does not establish, in one place.
//
// Three documents can be signed here — the catalog report, the compliance
// report and the seal verification — and until now only one of them said what
// it failed to prove. That asymmetry is the dangerous kind: the artifacts that
// look most authoritative are the ones a reader is least likely to qualify, and
// a signature makes a document look authoritative regardless of what is in it.
//
// The wording is the deliverable, so it lives here rather than being retyped at
// each call site, and writeSignable refuses to sign a document without it.

// signingLimits are true of every signed document this gateway produces,
// whatever it is about.
//
// Both lines exist because the signature means less than the word suggests: it
// is made with a key the audited party holds, on data that party controls. That
// is worth saying on every document rather than assuming an auditor infers it.
func signingLimits() []string {
	return []string{
		"The signing key is held by the operator of this gateway — the party being audited. " +
			"A signature proves this document was not altered after it was produced; it does not " +
			"prove the data it was built from was complete or untouched beforehand.",
		"There is no external anchor (RFC 3161 timestamp authority, transparency log, or a copy " +
			"held by a third party), so nothing here is independent of the operator.",
	}
}

// catalogReportLimits qualify the passive API inventory.
//
// Its central limit is structural rather than a shortcoming to be fixed: a
// catalog built from observed traffic can only contain what was called. "Not in
// this report" therefore means "not seen", never "not there" — and that is the
// opposite of what a reader wants it to mean when they are looking for
// forgotten endpoints.
func catalogReportLimits() []string {
	return append([]string{
		"This inventory is built from traffic that passed through the gateway. An endpoint that " +
			"was never called in the window does not appear: absence here means it was not " +
			"observed, not that it does not exist.",
		"Paths are normalised (/users/42 becomes /users/{id}), so one row can represent many " +
			"distinct resources, and a route that encodes data in the path may be collapsed with " +
			"unrelated traffic.",
		"On a mirrored deployment the copy carries no response, so PII classification, " +
			"object-ownership findings, status codes and latency are absent for that traffic " +
			"rather than negative.",
	}, signingLimits()...)
}

// complianceReportLimits qualify the framework mapping.
//
// The first line is the one an auditor most needs and a vendor least likes: a
// mapped control is evidence that a check ran, never evidence of compliance.
// The document already lists controls it cannot evidence at all (not_evidenced);
// these are the limits of the ones it does.
func complianceReportLimits() []string {
	return append([]string{
		"A mapped control shows that AEGIS produced evidence relevant to it. It is not an " +
			"assessment, and it is not a statement that the organisation complies with that " +
			"control — most controls cover process and governance that a gateway cannot observe.",
		"Controls this gateway cannot evidence at all are listed per framework under " +
			"not_evidenced. That list is part of the document and is not a rendering artifact.",
		"A static finding says an endpoint CAN be abused; only the runtime counts say that abuse " +
			"was detected. Controls that require detection are marked accordingly and are not " +
			"satisfied by findings alone.",
		"Evidence covers the window stated in this document and only the traffic that reached " +
			"this gateway. Anything routed around it is outside the record.",
	}, signingLimits()...)
}

// sealReportLimits are what a reader must not conclude from a green integrity
// result.
//
// Every line is a claim the mechanism cannot support, written out because the
// alternative is that somebody quotes "verified" and means something stronger
// than the code can deliver.
func sealReportLimits() []string {
	return append([]string{
		"Seals make deletion detectable, not impossible. Nothing here prevents a DELETE.",
		"A seal covers a period, not a row: an altered period is named, the missing entry is not, " +
			"and a Merkle root is not a backup.",
		"An operator holding the signing key can rewrite the chain, move the head and re-sign " +
			"both, producing a result that verifies.",
		"An operator who deletes the chain head together with every seal leaves a state that " +
			"cannot be distinguished from a deployment where sealing was never enabled.",
		"The accurate word is tamper-evident, never tamper-proof.",
	}, signingLimits()...)
}
