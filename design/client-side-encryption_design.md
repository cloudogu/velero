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
One to two paragraphs that describe the high level changes that will be made to implement this proposal.

## Detailed Design
A detailed design describing how the changes to the product should be made.

The names of types, fields, interfaces, and methods should be agreed on here, not debated in code review.
The same applies to changes in CRDs, YAML examples, and so on.

Ideally the changes should be made in sequence so that the work required to implement this design can be done incrementally, possibly in parallel.

## Alternatives Considered
If there are alternative high level or detailed designs that were not pursued they should be called out here with a brief explanation of why they were not pursued.

## Security Considerations
If this proposal has an impact to the security of the product, its users, or data stored or transmitted via the product, they must be addressed here.

## Compatibility
A discussion of any compatibility issues that need to be considered

## Implementation
A description of the implementation, timelines, and any resources that have agreed to contribute.

## Open Issues
A discussion of issues relating to this proposal for which the author does not know the solution. This section may be omitted if there are none.
