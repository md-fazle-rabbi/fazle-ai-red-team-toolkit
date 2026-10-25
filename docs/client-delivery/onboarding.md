# Client onboarding

This is the checklist I follow before any request leaves this toolkit for a client
system. It is a process I wrote, not a certified one, and no client engagement has
used it yet. Nothing in it is legal advice. The parts marked "enforced" are checked by
the Rules of Engagement loader in `src/redteam_toolkit/roe.py`. Everything else is a
habit that nothing checks.

## 1. What I need from the client before I write anything

| Item | Why | Enforced by the loader? |
| --- | --- | --- |
| A signed document that names the targets, the testing window and the allowed techniques. A statement of work or an authorization letter counts. A chat message or a verbal OK does not. | It is the authority for every request. | Only that a `signed_document` carries a SHA-256. Whether the signature is genuine is a human check. |
| The name, role and email of the person who has the authority to grant it (`authorized_by`). | The report names them. | Yes, all three fields are required. |
| A stop contact who can tell me to halt at once (`stop_contact`). | SECURITY.md says to stop when the owner asks. | Yes, the field is required. |
| For a production target, a second person to approve it (`production_approval`). | One person should not approve their own production test. | Yes. It is required for production and must be a different email from `authorized_by`. |
| Written confirmation that the target holds synthetic data only. | Real personal data is out of scope. | The file must say `real_personal_data = false`. The loader cannot check what the target really holds. |
| Test credentials limited to the test. They are revoked when the work ends. | Least privilege. | Only the name of an environment variable goes in the file, never the secret. |
| The limits the client will accept: requests per minute, total requests, requests in flight. | The target may be slow or have a free tier limit. | The code ceilings are 120 per minute, 10,000 in total and 10 at once. A file can ask for less. |
| A testing window of 31 days or less. | A short window limits exposure. | Yes. The window needs a UTC offset, and the end is exclusive. |

For a staging or production target the base URL must be https. For a `local` target the
host must be localhost, 127.0.0.1 or ::1.

## 2. Build the file

1. Copy the closest example from `examples/` into `engagements/`. That folder is
   git-ignored, so a client file never lands in the repository. Check with
   `git check-ignore engagements/<name>.toml`.
2. Fill in every field. The schema is strict, so a misspelled key is rejected.
3. For a `signed_document`, record the document's hash:
   `sha256sum signed-authorization.pdf`. Put the result in `authorization.sha256`.
4. List only the suites the client agreed to in `allowed_suites`, and only the paths
   they named in `allowed_paths`.
5. Validate: `uv run redteam-toolkit validate --file engagements/<name>.toml`.
6. Check each target, suite and URL I plan to use:
   `uv run redteam-toolkit check --file engagements/<name>.toml --target <id> --suite <suite> --url <full url>`.
   A refusal exits with 2 and sends nothing.

## 3. Kickoff call

Agree these out loud and write them in the engagement notes:

- The target list, the paths, the suites and the window, matching the file.
- Who can stop the test, and how fast they can be reached during the window.
- What the client will do if I report a serious finding mid-test.
- Where findings go, and who may read the report. The report holds counts and ids and
  no prompt text or answer text.

## 4. Dry run before the first client request

Run the same commands against the local stub first, with the same toolkit version.
Confirm the exit codes are what the README says. This shows the toolkit works on my
machine. It says nothing about the client system.

## 5. Go or no go

I do not send anything until every line is true:

- [ ] The signed document is in hand, and its hash is in the file.
- [ ] `validate` and every `check` I need exit with 0.
- [ ] The client confirmed synthetic data only, in writing.
- [ ] The stop contact is reachable for the whole window.
- [ ] Test credentials are issued, and I know the revoke date.
- [ ] The file sits in `engagements/` and is not committed.

## What this does not cover

- The gate checks what the file says. It cannot tell whether a signature is real.
- The URL check compares text, not the address a name resolves to.
- garak sends its own requests, so the gate binds it only through the local proxy.
  Running `check` by hand first is a habit, not enforcement.
- Rituals during the engagement and offboarding are separate documents.
