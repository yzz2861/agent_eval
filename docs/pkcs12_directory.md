# PKCS#12 Read-only Directory

The PKCS#12 directory reconciler inspects only public container material. It
does not decrypt password-protected content and it never copies private key or
secret bag material into a report.

    from asn1crypto import pkcs12

    report = pkcs12.directory(pfx_bytes, registry)

The registry may be a list of records, a mapping of friendly names to records,
or objects with matching attributes. A record can include record_id,
friendly_name, sha256, sha1, local_key_id, serial_number, issuer, subject or a
certificate object. Only public certificate identifiers are read from a
certificate object.

The report has five sections:

 - resolved: certificate bags bound to a registration by certificate
   identifier or by a unique friendly name
 - conflicts: friendly-name groups where more than one entry or registration
   uses the same name
 - not_visible: encrypted safe contents, encrypted private keys, redacted
   private keys, secret bags and unreadable placeholders
 - unmatched: visible certificates that have no registration claim
 - catalog: every entry found, including containers, with its complete path

Each entry keeps the path from the top-level auth_safe through
authenticated_safe indexes and nested safe_contents indexes. Every entry also
has a placeholder flag, a material_visible flag and a container dictionary so
an identity binding cannot lose its original position or its unavailable
state.

    report['resolved']
    report['conflicts']
    report['not_visible']
    print(report.format_review_table())

A shared friendly name is not proof of ownership. If two entries use the same
name, an entry is claimed only when its certificate identifier matches a
registration, or when it is the only visible certificate with that name and the
registration name is unique. Other entries stay in the conflict section with
an explanation of why they cannot be claimed.
