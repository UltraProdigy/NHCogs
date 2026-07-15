# Pre-update Discord checklist for the detection-case hard cutover

This checklist is required because the new cog intentionally does not migrate legacy `pending_reviews` or legacy temporary-review mute ownership.

## Legacy review queue must be empty

- Resolve every unresolved legacy review card using its Ban, Kick, or Ignore control.
- Check the entire configured review destination, including older messages outside the currently visible recent history.
- Confirm there are no review cards still showing active controls or a future expiry.
- If a card cannot be resolved through its controls, record the target user ID and resolve its containment manually before the update.

## Legacy review mute role must have no remaining recipients

- Identify the role configured as the Honeypot review/mute role.
- Inspect every member who currently has that role.
- For each member, determine whether the same role is also legitimately owned by another system, especially Joinwatch.
- Remove the role only when Honeypot review is its last owner. Do not bulk-remove a shared role without checking Joinwatch ownership.
- The safe pre-update state is: no user has a review mute that depends on a legacy pending review timer.

## Joinwatch state must be settled separately

- Legacy pending review and Joinwatch are different ownership domains even if they use the same Discord role.
- Leave legitimate Joinwatch auto-role assignments in place.
- Resolve or acknowledge any outstanding Joinwatch alerts and retry timers.
- Verify that members whose Joinwatch role should remain are not accidentally included in manual review-role cleanup.

## No unresolved moderator action should be in flight

- Wait for Ban/Kick/Ignore interactions to finish responding.
- Confirm the intended bans and kicks in Discord's audit log.
- Confirm any expected modlog entries were created.
- Do not update while moderators are actively pressing controls or while a review action is visibly loading.

## Review destination must be ready for the new model

- Configure a normal guild text channel, not an existing thread, as the review destination.
- The bot must be able to view the channel, send messages, read message history, embed links, attach files, create public threads, send in threads, and manage threads.
- Verify the bot's highest role and channel overrides do not deny those permissions.
- Keep enough channel/thread visibility that the moderator team can access newly created case threads.

## Bait and containment roles must be unambiguous

- Bait role must be a dedicated trap role.
- Bait role must not be the review mute role.
- Bait role must not be the Joinwatch auto-role.
- Confirm no normal member currently has the bait role before enabling or restarting the updated cog.

## Final update gate

- Export or screenshot the legacy review queue and current holders of review/Joinwatch/bait roles.
- Back up Red Config and the cog data directory.
- Stop moderator activity for the short update window.
- Recheck that legacy pending review count is zero immediately before stopping the old cog.
- After update, run the cog doctor/config checks before triggering a real detection.
- Perform one canary case and verify summary, thread, evidence, action, role release, modlog, and archive/lock behavior.
