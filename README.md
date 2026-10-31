# OKG Webmail

A Dockerfile-based, self-hosted webmail client for existing IMAP/SMTP mailboxes. Designed for Blitz deployments without Docker Compose.

## Features

- Individual OKG Webmail accounts with password hashing.
- Invite-code-gated registration.
- Each staff member can connect their own FounderMail mailbox.
- Inbox listing, message reading, reply-by-compose, and outbound email.
- Both IMAP and SMTP credentials are tested before a mailbox is saved.
- SMTP uses mandatory STARTTLS; IMAP uses SSL/TLS.
- Session-bound CSRF protection on state-changing forms.
- Mailbox passwords encrypted at rest with AES-256-GCM.
- SQLite database and session store under `DATA_DIR` (default `/data`).
- Responsive mobile-friendly interface.

## Required environment variables

Set these in the Blitz service settings. Never commit real values into GitHub.

- `SESSION_SECRET`: random secret, at least 32 characters.
- `ENCRYPTION_KEY`: a different random secret, at least 32 characters. Losing/changing this key makes saved mailbox passwords unreadable.
- `REGISTRATION_CODE`: private code shared only with OKG staff. Without it, registration is disabled.
- `DATA_DIR=/data`
- `NODE_ENV=production`
- `PORT=3000` (or use the port required by the hosting platform).

Generate two independent secrets locally with a password manager or a cryptographically secure random generator. Do not reuse the registration code as either secret.

## Blitz deployment

1. Create a Docker-based service from this repository; Blitz should build from the root `Dockerfile`.
2. Add the environment variables above.
3. Attach persistent storage mounted at `/data`. Without persistent storage, users and mailbox connections can be lost on redeploy/restart.
4. Ensure Blitz provides HTTPS before using real email credentials.
5. Deploy and visit `/health`; a healthy response is JSON with `ok: true`.
6. Give staff the registration code privately. Each person creates their own account and connects their own mailbox.

## Mail server settings

FounderMail settings are fixed server-side to prevent arbitrary mail-server connections:
- IMAP: `imap.foundermail.mx:993` (SSL/TLS)
- SMTP: `smtp.foundermail.mx:587` (mandatory STARTTLS)
- Username: the full mailbox email address
- Password: the mailbox password from the FounderMail mailbox page

The application verifies both incoming and outgoing authentication before saving the mailbox. Actual sends remain subject to FounderMail's verified-domain, outbound-recipient, and monthly allowance rules.

## Important security notes

- Never share an OKG Webmail login or mailbox password.
- Keep `SESSION_SECRET`, `ENCRYPTION_KEY`, and `REGISTRATION_CODE` private.
- Keep the service behind HTTPS. Do not use it for real mail until it has been tested with a non-sensitive mailbox.
- The app stores mailbox passwords encrypted, but the server must decrypt them to connect to the mail provider. Anyone with server access and the encryption key could access them.
- Back up the persistent `/data` volume securely. Keep the encryption key backed up separately.
- This is an initial version and has not had an independent security audit.
