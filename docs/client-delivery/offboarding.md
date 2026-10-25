# Engagement offboarding

How I close an engagement after the testing window ends or the client stops it. The
steps are my own habits. No client engagement has used them yet, and nothing in the
toolkit enforces them, except the points marked "enforced". Nothing here is legal advice,
and any retention period comes from the client agreement, not from this file.

## 1. Stop sending

- The gate refuses every request from the end of the window on (enforced). The end is
  exclusive.
- If the client ends the work early, I stop at once, and I write down the time and who
  told me. I do not wait for the window to close.
- I stop any local proxy that is still running, and I make sure no scheduled job still
  points at the client.

## 2. Revoke access

- The client revokes the test credentials. I ask for a written confirmation, because I
  cannot check it myself.
- I remove the credential from my environment and shell history. The file only ever held
  the name of the variable, never the secret.
- If a credential showed up anywhere it should not be, such as a log or a message, I
  tell the client so they can rotate it.

## 3. Build the final report

1. Run `redteam-toolkit report` with the file and every summary I want in it. It exits 3
   when a summary cannot be judged, so I fix that run or leave it out and say why.
2. Read the Limitations section before sending. A result against a target describes
   that target in that window and nothing else.
3. The Findings section lists a weakness only when a result showed it. A clean run is
   not a statement that the target is secure, and I say so when I hand it over.
4. Record the report's SHA-256: `sha256sum <report>.md`. I send the hash with the report,
   so the client can tell it was not changed later.

## 4. Hand over

- The client gets the final report, the Rules of Engagement file that was used, and its
  SHA-256 as printed by `validate`.
- They can also get the summary files for the runs in the report. The summaries hold
  counts and ids and never probe or answer text.
- I do not hand over raw answers or any probe text unless the client asks in writing,
  and then I check first that nothing in them is real personal data.
- I offer a short call to walk through the findings. I do not argue about severity there.
  The CVSS scores in the catalogue are my judgement, and the client may weigh them
  differently.

## 5. Clean up my side

- Delete what I do not need to keep: the audit files, summaries and any answer dumps
  under `runs/`, and anything else the engagement produced outside the final report.
- Keep, for the period agreed with the client: the final report, its hash, the Rules of
  Engagement file and the signed document. If no period was agreed, I ask for one in
  writing rather than choosing it myself.
- Check that nothing from the engagement is committed. `git status` should show no
  engagement file, and `git log` should show no client name.

## 6. Close out in writing

I send the client a short note that says:

- The window ended, or the work was stopped, at this time.
- Access has stopped on my side, and I asked them to confirm the credentials are revoked.
- What I kept, what I deleted, and for how long I keep the kept items.
- Where to send any question about the work.

## 7. Learn from it

- I write down what went wrong in the process, such as a missing item at onboarding or
  a stop rule that was unclear. I fix the three documents here, and the toolkit if the
  cause was in the code.
- If the toolkit missed something, such as a detector that did not fire, I add a test
  or an entry to the exploit library, and I follow the refresh cadence in
  [ADR-003](../adr/ADR-003-exploit-library-refresh-cadence.md).
- I do not put the client's name or data in the repository. A lesson is written in
  general terms.

## What this does not cover

- It cannot confirm the client revoked anything.
- It cannot delete copies of the report that the client or I shared.
- It does not set a legal retention period.
