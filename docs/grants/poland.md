# Poland — company, grants, investors

> Working document. Based on open sources as of **2026-09-24**. Before
> submitting anything, read the official documentation for the specific call on
> the PARP or NCBR site — not this file. Grant programmes change their rules
> between rounds, and a secondary source is a starting point, never an
> authority.
>
> Companion to [`eic-accelerator-roadmap.md`](../eic-accelerator-roadmap.md),
> which covers the EU-level track. Poland is not an alternative to EIC — it is
> the jurisdiction that makes EIC possible, and it has its own money on a much
> shorter timeline.

---

## 0. The one thing that changes the plan

**PARP Ścieżka SMART, the SME call: applications 29 October – 29 December
2026.** That is five weeks from now for the window to open and roughly three
months to submit.

Pool around 700 mln PLN, up to 50 mln PLN per project, up to 80% of eligible
industrial-research costs for a micro or small enterprise. That is the largest
non-dilutive instrument realistically open to a Polish company of this size,
and the calendar means the company registration is now on a deadline rather
than on a wish.

Second track for completeness: **NCBR runs 7 August – 16 October 2026**, but
that path is oriented to consortia and large enterprises, so it is not ours.

---

## 1. The trap in an R&D grant, and it is the opposite of the investor pitch

This is the part worth reading twice.

An investor asks "how finished is it" and rewards maturity. **Ścieżka SMART's
mandatory module is R&D** — the applicant must show research and development
work that creates something innovative. A product presented as finished has no
R&D left to fund, and the application fails on its own success.

So the two documents are genuinely different, and neither is dishonest:

| | Investor / customer | Ścieżka SMART |
|---|---|---|
| Emphasis | What works today, verifiably | What is not yet solved, and the credible plan to solve it |
| Our strongest asset | The working system, the measured overhead, the signed evidence | The list of open problems in `ROADMAP.md` §3 |
| Weakness to disclose | No customers yet | — (the absence of a finished product is the point) |

The good news is that no invention is required for the second one. The roadmap
already maintains an honest list of unsolved problems, and three of them are
real research with real technical risk:

- **External anchoring of tamper-evident records.** Everything today lives in
  the customer's own database, so an operator holding the signing key can
  rewrite a record and re-sign it. Anchoring a Merkle root outside the
  operator's control — RFC 3161 timestamping, a transparency log — without
  sending customer data anywhere is a genuine design problem, and it is the
  academic core of "evidence a regulator can rely on from a self-hosted
  system". This is the strongest work package we have.
- **Behavioural detection without training data.** Per-consumer online
  baselines ship today across four dimensions. Extending to call-sequence
  anomalies and peer-group comparison, while keeping every finding explainable,
  is research: the trade-off between detection power and explainability is
  exactly what a reviewer will recognise as non-trivial.
- **Out-of-band sensing at line rate.** Mirror mode works, but an eBPF sensor
  that observes API traffic without an inline hop and without a copy leaving
  the host is a different technical problem with a measurable outcome.

Each of those has a measurable success criterion, which is what an assessment
form asks for and what a vague "we will improve the product" cannot supply.

---

## 2. Formal requirements, and which of them we do not meet yet

From the published criteria for the SME call:

| Requirement | Us |
|---|---|
| Registered in Poland (KRS), micro/small/medium | **To do** — this is the blocking item |
| No arrears with the tax office or ZUS | Trivially met by a new entity |
| Not an "enterprise in difficulty" | Watch this: a company whose accumulated losses exceed half its share capital can fall into this category. Capitalise accordingly rather than at the 5 000 PLN minimum |
| Ability to finance the own contribution (20–75% depending on module) | **The real question.** Reported practice is that own funds may not require documentary proof, but "may" is doing a lot of work in that sentence and it must be confirmed against the call documentation |
| Mandatory R&D module | Covered by §1 above |

**The own-contribution point is the one to settle first.** At 80% intensity on
industrial research, a 1 mln PLN project still needs 200 000 PLN that the
company can show it is able to spend. Learning the answer in December is too
late.

---

## 3. Order of operations

1. **Register the sp. z o.o.** Everything else depends on it, and the October
   window does not move. Capitalise above the minimum for the "enterprise in
   difficulty" reason above.
2. **Confirm the own-contribution rule** for this specific call, in writing,
   from PARP's own documentation or their information point — before writing
   the application, not after.
3. **Write the R&D work packages** from `ROADMAP.md` §3. The material exists;
   what it needs is the programme's structure — objectives, measurable results,
   risk, budget per package.
4. **Keep the two documents separate.** `docs/product-brief-en.md` for
   investors and customers; the grant application leads with unsolved problems.
   The same facts, different emphasis, and neither one overstating.
5. **EIC Accelerator stays the larger prize** but needs TRL 6+, which needs a
   pilot. Polish registration serves both: EIC requires an entity in an EU or
   associated country, and Ścieżka SMART can fund the work that raises TRL.

---

## 4. What not to do

**Do not dress the product up to look more finished than it is.** For an
investor it is transparent — they check, and a dressed-up deck loses the round
and the reputation. For a grant it is worse than useless: assessors verify
claims, misrepresentation is disqualifying, and on an R&D programme a finished
product is a reason to reject rather than to fund.

The whole engineering discipline of this project has been refusing to claim
more than the code proves. That discipline is now a commercial asset: it means
every number in the brief can be reproduced on request, and there is nothing in
it that a due-diligence process can turn over.

**Do not copy the incumbent's presentation.** Akamai's demo opens with customer
logos, scale figures and certifications. We have none of the three, and a deck
shaped like theirs reads as an empty imitation of a company rather than as a
small company with a real product. What we have that they cannot show is that
every claim is verifiable in twenty minutes on a laptop.

---

## Sources

Checked 2026-09-24; secondary reporting, to be confirmed against the official
call documentation.

- [PARP — Ścieżka SMART, R&D projects](https://www.parp.gov.pl/component/grants/grants/sciezka-smart)
- [PARP — 700 mln zł and new rules for Ścieżka SMART](https://www.parp.gov.pl/component/content/article/90037:700-mln-zl-i-nowe-zasady-gry-nowa-jakosc-sciezki-smart)
- [PARP — question-and-answer base for Ścieżka SMART](https://pytania.parp.gov.pl/kategoria/nowe-produkty-i-inwestycje/sciezka-smart)
- [Ścieżka SMART FENG 2026: PARP and NCBR calls](https://mdotacje.pl/sciezka-smart-parp-2026/)
- [Ministry of Funds — 2025/2026 FENG call schedule update](https://www.archiwum.nowoczesnagospodarka.gov.pl/strony/aktualnosci/aktualizacja-harmonogramu-naborow-na-2025-i-2026-r-w-programie-fundusze-europejskie-dla-nowoczesnej-gospodarki-2021-2027/)
