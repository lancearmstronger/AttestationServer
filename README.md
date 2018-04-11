## API for the Auditor app

### QR code

The scanned QR code contains space-separated values in plain-text: `<domain> <userId>
<subscribeKey> <verifyInterval>`. The `subscribeKey` should be treated as an opaque string rather
than assuming base64 encoding. Additional fields may be added in the future.

### /challenge

* Request method: POST
* Request headers: n/a
* Request body: n/a
* Response body:

Returns a standard challenge message in the same format as the Auditor app QR code. The challenge
can only be used once and expires in 1 minute.

The server challenge index *may* rotate. Ample time will be provided for subscribeKey rotation to
be propagated before the challenge index is rotated.

### /verify

* Request method: POST
* Request headers:

The `Authorization` header needs to be set to `Auditor <userId> <subscribeKey>` for an unpaired
attestation. That will also work for a paired attestation if the subscribeKey matches, but it
should be set to `Auditor <userId>` to allow for subscribeKey rotation.

* Request body:

Standard attestation message in the same format as the Auditor app QR code.

* Response body:

Returns space-separated values in plain text: `<subscribeKey> <verifyInterval>`. Additional fields
may be added in the future.
