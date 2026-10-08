# SCPFS command files

Status: implemented and verified against the isolated real OpenSSH/Linux, WinFsp and SCM fixtures in Debug and Release, plus Close/Rename submissions on the configured production R: service; see `VALIDATION.md` for exact scope and remaining unknowns.

The user specified an exact command-file protocol: the literal basename `.in.txt` triggers on user Close or Rename, runs commands in the uploaded directory, is removed after processing, and writes its result to `.out.txt` in the same directory. Names are case-sensitive; `.IN.TXT` and `job.in.txt` are ordinary files.

## Events and ordering

Ordinary Flush only commits file data. WinFsp's Cleanup callback is treated as the last user-handle close, so `PostCleanupWhenModifiedOnly=0` ensures clean and read-only handles receive it; Cleanup first commits a regular file whose final basename is `.in.txt`, then submits it. The later Close callback is only a fallback when Cleanup never ran. Renaming a regular file to that exact basename commits and renames before submission. No directory scan, polling, startup execution or traversal of renamed directories occurs. A clean/read-only open of an already existing `.in.txt` also qualifies on Cleanup/Close, as the requested trigger is user close itself.

Each handle records whether submission was attempted. Rename consumption suppresses later Cleanup/Close triggers and prevents the consumed handle from reuploading the command file. Failed payload commit never executes commands. Backend processing atomically claims the input by moving it to a cryptographically random sibling before execution, so another event cannot submit the same path at the same time. If the input is already absent when a delayed close arrives, that close is a benign no-op.

Clean metadata-only handles own no payload cache. A metadata Close/Cleanup encountering an active payload owner launches nothing and leaves the trigger to that owner's Close; it does not retry later. Other active/unresolved conflicts are recorded as known-not-launched recovery before dispatch. Explicit Rename checks ownership before even a same-path submission. Namespace changes and input consumption invalidate old clean metadata peers, whose later Cleanup/Close cannot execute a newly created script at the old pathname.

## Command and result contract

Input is UTF-8 POSIX shell text interpreted by `/bin/sh` from a normalized script file, with LF or CRLF and an optional UTF-8 BOM. It is not a configured executable name or a template interpolated by SCPFS. The remote shell runs with the authenticated SSH account's permissions; its working directory is the command file's parent. Input is limited to 1 MiB; invalid UTF-8, NUL or oversized input produces an explanatory result and is consumed without running commands.

Standard output and standard error are combined into a private output spool. Successful output is raw command output, without an added exit-code prefix. Captured output is limited to 8 MiB, with a truncation marker where applicable. Publication atomically replaces the sibling `.out.txt`; symlink/special-file targets are rejected. Completed commands, including nonzero exits and timeout, publish output and remove the claimed input. The exit code is logged separately. The default command timeout is 30 seconds, with a bounded kill grace period; the CLI may override it with `--command-timeout-ms` up to 540000 ms (540 seconds).

The configured filesystem root controls path mapping, not a shell security sandbox. The user intentionally supplied shell commands. Processing `.in.txt` is reserved behavior, not ordinary text-file storage.

## Failure and recovery

The backend result distinguishes input consumption, completion, output publication and unknown outcome, and returns the retained claim path when available. Network loss after launch can make the command's outcome unknown. SCPFS does not blindly replay commands; the claim/spool and local recovery information are retained for inspection. Exactly-once execution across remote crashes or network partitions is not claimed.

Close cannot return an NTSTATUS, so processing failures are logged with recovery information. Rename can report setup/protocol failure, but a successfully completed command with a nonzero exit is still a consumed submission, with its output and exit code available. Upload success and command exit status remain separate facts.

## Required verification

Real SSH/WinFsp tests cover direct Close submission, rename into `.in.txt`, no execution during multiple Flush calls, later Close deduplication, parent working directory, combined output, input removal, atomic result replacement, case-mismatched ordinary files, CRLF/BOM handling, nonzero exit and bounded timeout. Unknown-outcome recovery must remain explicit if not tested. Static EXE imports and public-key-only authentication are independent mandatory gates.
