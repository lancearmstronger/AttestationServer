## API for the Auditor app

### QR code

The scanned QR code contains `<domain> <userId> <subscribeKey> <verifyInterval>`.

### /challenge

* Request method: POST
* Request headers: n/a
* Request body: n/a
* Response body:

Returns a standard challenge message in the same format as the Auditor app QR code. The challenge
can only be used once and expires in 1 minute.

The server challenge index *may* rotate.

### /verify

* Request method: POST
* Request headers:

The `Authorization` header needs to be set to `Auditor <token>` where `<token>` is a JSON object
with the `userId`. For an unpaired attestation, it also needs to have the `subscribeKey`. The
`subscribeKey` should not be sent for a paired attestation to allow for key rotation.

* Request body:

Standard attestation message in the same format as the Auditor app QR code.

* Response body:

Returns a JSON object with `subscribeKey` and `verifyInterval` fields. The `subscribeKey` should
be saved and used in the future if a new pairing is required due to a challenge index rotation.
The `verifyInterval` field is an integer with the time (in seconds) until the next attestation
should be submitted.
