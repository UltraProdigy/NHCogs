from datetime import datetime, timedelta, timezone
from contextlib import closing
import json


_TEST_EVIDENCE_LIMIT = 1 << 40


def capture_attachment(store, case_id, message_sequence, position, evidence_path):
    snapshot = store.get_case(case_id)
    attachment = next(
        item
        for item in snapshot.attachments
        if item.message_sequence == message_sequence and item.position == position
    )
    now = datetime.now(timezone.utc)
    reservation = store.reserve_attachment_capture(
        case_id,
        message_sequence,
        position,
        attachment.size,
        now,
        stale_before=now - timedelta(minutes=5),
        max_attachment_bytes=_TEST_EVIDENCE_LIMIT,
        max_case_bytes=_TEST_EVIDENCE_LIMIT,
    )
    if reservation.status != "claimed":
        return False
    return store.complete_attachment_capture(
        case_id,
        message_sequence,
        position,
        reservation.claim_token,
        attachment.size,
        str(evidence_path),
        now,
        max_attachment_bytes=_TEST_EVIDENCE_LIMIT,
        max_case_bytes=_TEST_EVIDENCE_LIMIT,
    ) == "captured"


def publish_primary(store, case_id, channel_id, message_id):
    token = store.claim_publication(case_id, "primary", datetime.now(timezone.utc))
    return token is not None and store.complete_primary_publication(
        case_id, token, channel_id, message_id
    )


def publish_evidence(
    store, case_id, batch_index, channel_id, message_id, attachment_keys=()
):
    encoded_keys = json.dumps(
        [[key.message_sequence, key.position] for key in attachment_keys],
        separators=(",", ":"),
    )
    with closing(store._connect()) as connection, connection:
        result = connection.execute(
            """INSERT OR IGNORE INTO detection_evidence_publications
               (case_id, batch_index, channel_id, message_id, attachment_keys)
               VALUES (?, ?, ?, ?, ?)""",
            (case_id, batch_index, channel_id, message_id, encoded_keys),
        )
        return result.rowcount == 1
