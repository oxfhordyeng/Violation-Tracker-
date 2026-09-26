# Astral Cosmic Eunoia Violation Tracker

A moderation dashboard for logging community reports, assigning status and severity, searching cases, and exchanging records with the shared Google Sheet. A server-managed passcode protects the member portal.

## Run

Copy `.env.example` to `.env` and replace `PORTAL_PASSCODE` with a private passphrase of at least 12 characters. Keep `.env` private; it is ignored by Git. Start the portal with `npm start` and open `http://localhost:8080` (or use the existing Chrome launch configuration).

The passcode is checked by the Node server and never sent as part of the page. Successful sign-ins receive an HttpOnly, SameSite session cookie that expires after 12 hours. Login attempts are rate-limited. In production, serve the portal over HTTPS so session cookies are secure.

This version uses one shared passcode, not individual member accounts. Case records remain in each browser's local storage, so different members do not yet share a live case database.

## Google Sheets workflow

The tracker links to the community spreadsheet: [Open the Google Sheet](https://docs.google.com/spreadsheets/d/1MN1lXTlbsdIkfdsejcjSiORPvK9NTbI09naYtPlOTSA/edit?usp=sharing).

Use **Export CSV** to download tracker records, then import that CSV into the sheet. Use **Import CSV** to bring sheet records into the tracker. Imports match on `case_id` and update matching records; rows without an ID are assigned one. The tracker does not write directly to Google Sheets; automatic two-way sync requires a Google-authorized integration such as an Apps Script web app.

CSV import expects `username`, `category`, and `status` columns. It also recognizes `case_id`, `severity`, `reported_at`, `moderator`, and `notes`.
