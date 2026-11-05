# Classification and evidence policy: edge cases

Policy version is unchanged: `ps010-policy-1`. No label, reason code or classifier rule was changed
by the source-health work. The decisions below document **current behaviour** and are pinned by
`tests/test_evidence_policy_edge_cases.py`. Any change needs a separate proposal, explicit approval,
its own tests and, where required, a new policy version.

**A. Tor/VPN overlap with a failed source.** With every source healthy, a Tor match plus a VPN
match is a conflict and resolves to `Unknown` / `UNKNOWN_CONFLICTING_EVIDENCE`. If the VPN source
(or the Apple list when it matters) is down, the conflict cannot be seen and a Tor match stands as
`Known Tor exit` with the outage listed in the caveats; the mirror case holds for a VPN match when
the Tor list is down. Decision: keep (conservative on labels, visible via caveats). Open question:
whether a failed *other* kind should downgrade a positive to `Unknown`. That would be a policy
change and is not proposed here.

**B. Apple exclusion-list outage.** The label is conservative (`Unknown`), but the reason code is
the broad `UNKNOWN_NO_QUALIFYING_MATCH` and the outage is visible only as a caveat. Decision: keep.
Source-health reporting adds visibility outside classification (health report, `role: exclusion`).

**C. Tor exit inside an Apple-excluded range.** The Apple range is not VPN evidence, so there is
no conflict; the label is `Known Tor exit`. Decision: keep.

**D. Observation window.** Current-only snapshots apply when the observation time is within the
tolerance (default 3600 s) on **either** side of the retrieval time, so an observation up to an
hour *before* retrieval is treated as current. Decision: keep and document; a snapshot cannot
actually prove status before it existed, but the rule is symmetric by design.
