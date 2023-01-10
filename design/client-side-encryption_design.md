# Proposal for client-side encryption

## Abstract
Currently only PersistentVolumes are stored in a Restic/Kopia repository, which means that only they are encrypted and the rest of the backup is not.
It is desired that the whole backup can be encrypted which overall will lead to better security.

## Background
As of today, Velero stores only PersistentVolume data in a Restic/Kopia repository.
This repository is encrypted while the rest of the backup (Kubernetes and backup metadata) is not.
Backups should be safe against illegal access and tampering.
It is therefore desired to have the ability to store this data in an encrypted manner.

## Goals
- Encryption of all the files of a backup with AES.
- Basic configuration of the encryption, e.g. turning it on and off.

## Non Goals
- Other ciphers than AES (can be added later)
- Encrypting the whole backup as a single entity (versus encrypting every file separately)
- Encrypting only certain files.


## High-Level Design
The encryption will happen during the backup process before the objects are persisted (e.g. written to an object store).
Decryption will happen during a restore after the persisted objects have been read.
The encryption key will be stored in a Kubernetes secret.
Encryption can be activated in the Velero configuration.

## Detailed Design
A detailed design describing how the changes to the product should be made.

The names of types, fields, interfaces, and methods should be agreed on here, not debated in code review.
The same applies to changes in CRDs, YAML examples, and so on.

Ideally the changes should be made in sequence so that the work required to implement this design can be done incrementally, possibly in parallel.

## Alternatives Considered
This could also be implemented in object store plugins.
Then however, it has to be implemented in every single object store plugin.
This is not viable.

We could just make use of server-side encryption of an object store.
But what about object stores that do not support this?
Also, client-side encryption is a lot safer, since the backups are encrypted during transit as well.

## Security Considerations
Overall this feature should increase the security of the product.
However, the security of this feature has to be ensured to avoid giving users a false sense of security. 

## Compatibility
What happens if encryption is activated when unencrypted backups already exist?
What about the reverse?

## Implementation
A description of the implementation, timelines, and any resources that have agreed to contribute.

## Open Issues
A discussion of issues relating to this proposal for which the author does not know the solution. This section may be omitted if there are none.
