# Firebase

- `firestore.rules` and `storage.rules` are the entire access-control layer.
  `allow read, write: if true;` is world-readable and world-writable; so is a
  rule guarded only by `request.auth != null` on data that belongs to specific
  users.
- Rules do not validate shape unless you write it. Without a `request.resource
  .data` check, any authenticated caller can write any field, including ones
  your client never sends.
- The Firebase web config (apiKey, projectId) is *not* a secret and is meant to
  ship to the browser. Do not report it. A **service account JSON** is the
  opposite: it is a full-project credential and must never be in the repo.
- Cloud Functions with no auth check are open endpoints regardless of rules.
- Default rule sets expire. A rule file with a hardcoded future date is a
  time bomb: report it.
