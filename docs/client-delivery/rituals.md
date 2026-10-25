# Engagement rituals

What I do between the go decision in [onboarding](onboarding.md) and the handover in the
offboarding document. These are habits I chose. No client engagement has used them yet,
and nothing in the toolkit forces any of them, except the points marked "enforced".

## Before every session

1. Confirm the window is open. The gate refuses a request before the start and from
   the end on (enforced), but I check first so I do not plan a session that cannot run.
2. Run `check` for each target, suite and URL I plan to use today. Exit 0 means the file
   permits it. Exit 2 means stop and find out why.
3. Confirm the stop contact is reachable today.
4. Confirm the target is not in a deploy, an outage or a client freeze. I ask the
   client. The toolkit cannot see this.

## During a session

- Every request goes through the gate and the request budget (enforced for the toolkit's
  own commands). For a third-party tool such as garak I point it at the local proxy
  with `redteam-toolkit proxy`, so the gate and the budget see its requests too.
- Only the proxy holds the file's `concurrency` limit. A run from several threads
  without the proxy has to hold the slots itself.
- Watch for a slow target, a rising error rate or odd failures. SECURITY.md says to stop
  at once, so I stop first and ask afterwards. Exit 3 from a run or a gate means the run
  could not be judged. It is never a pass.
- Output stays in `runs/`, which is git-ignored. Summaries hold counts and ids and never
  prompt or answer text. The proxy audit file holds the outcome of each request and
  never a request or response body.

## Stop rules

I stop the session and tell the stop contact the same day when any of these happens:

- The stop contact or the client asks me to.
- The target slows down, errors in an unexpected way or goes down.
- A request is refused for a reason I do not understand. A refusal means the file says
  no, so I do not retry it with another command.
- I see what looks like real personal data, a real secret or a credential in an answer.
  The file says synthetic data only, so this means the target is not what was agreed. I
  stop, I do not copy it anywhere, and I tell the client.
- The window is about to close and a run is half done. A half run with no summary is not
  a result, so I do not report it as one.

## Findings

- A result is a finding only when a check shows the weakness. The report's Findings
  section works that way. A clean run says that no finding met its threshold. It does
  not say the target has no weakness.
- If a finding looks serious, I tell the stop contact the same day and do not wait for the
  report. The CVSS scores in the catalogue are my judgement, so I do not quote one as a
  fact.
- I write a finding down with counts and ids only. No probe text and no answer text
  goes into a message, a ticket or a chat.

## Changing the scope

The file is the scope. If the client wants another target, path, suite or a longer
window, I do not edit the file in place. I get new written authorization, write a new
file, record its new hash and run `validate` and `check` again. The old file stays as
the record of what was agreed before.

## End of every session

1. Note what ran: the command, the target, the suite, the file's SHA-256 and the exit
   code. The SHA-256 is printed by `validate` and `check`.
2. Keep the summaries in `runs/`. Commit nothing from a client engagement.
3. Tell the client what ran and what did not, in a line or two. Status updates carry
   counts and exit codes, not probe text.
4. If a request budget is nearly used up, say so. The count starts at zero in every new
   process, so a new process does not continue the old total. I track the total by hand
   across processes.

## Weekly, for a window longer than a week

- Re-read the file against what the client said on the last call. If they differ, the
  file loses until the client confirms in writing.
- Re-check the threat map release and the exploit library against the refresh cadence in
  [ADR-003](../adr/ADR-003-exploit-library-refresh-cadence.md). Nothing enforces it.
- Generate a draft report with `redteam-toolkit report` from the summaries so far. It
  exits 3 when a summary cannot be judged, so a thin run cannot read as clean.

## What this does not cover

- It does not make a result true of a system I did not test. Against a stub it says
  nothing about a client system.
- It does not protect against me sending something outside the toolkit. A hand-made curl
  command is not gated.
