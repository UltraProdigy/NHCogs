# Deferred usability and rollout findings

Scope: findings from the `master...feature/detection-case-pipeline` review that are intentionally not part of the focused post-ban fix.

## Accepted rollout boundaries

- The hard cutover does not migrate legacy `pending_reviews` or their temporary mute ownership. Production must be drained before upgrade.
- A review destination configured directly as a Discord thread is no longer supported. The destination must be a normal text channel where the bot can create and manage public threads.

## Deferred confirmed findings

### Recovery and publication

- Rolling back to `master` with active new detection cases strands the new controls and may leave detection-owned containment roles in place.
- On Windows, `test_cancelling_coordinator_cancels_inflight_attachment_reads` is intermittent: a cancelled capture can briefly retain the SQLite file handle, causing `TemporaryDirectory` cleanup to raise `PermissionError`. The same unchanged test produced both passes and a cleanup-only failure during verification.

### Resources and retention

- Attachment capture uses `Attachment.read()`, so complete files are held in memory. With four capture slots and parallel attachments, large-file bursts can exhaust process memory. The preferred future change is streaming to disk, not restoring an arbitrary small file-size cap.
- Initial image scans have no global semaphore, allowing a resource burst across many simultaneous messages.

### Moderator presentation

- Timeline attachment capture errors intentionally retain explicit values such as `capture_timeout`, `capture_failed`, and `too_large`.
- New case UI strings largely bypass Red's translation layer and can produce a mixed-language UI.
- Embed projection can produce multiple pages, while Discord publication uses only the first page; detailed warnings may be absent from the summary while remaining in the thread.
- Source message links can be dead after deletion or unfurl and visually duplicate copied evidence.

### Documentation and operator safety


## Explicitly excluded by current user decision

- Do not change the two `Ignore` controls in this pass.
- Do not change the summary message list; the complete list in the case thread is accepted.
- Do not change image-control visibility based on the static review finding; prior Discord QA showed the tested flow behaving correctly.
