# Realm of Elements — Secure Supabase Setup

This version removes staff passwords from browser `localStorage` and removes the hardcoded admin password from the frontend.

## 1. Run the database migration

Open **Supabase → SQL Editor**, paste the entire contents of `supabase_security.sql`, and run it.

The migration creates:

- `admin_users` — identifies which Supabase Auth accounts are ROE admins.
- `staff_members` — stores staff profiles and one-way password hashes.
- `staff_sessions` — short-lived server-verified staff sessions.
- Secure RPC functions for creating, verifying, punishing, and deactivating staff.
- A server-side login-history writer that never stores the staff password.

## 2. Create the admin Auth account

In **Supabase → Authentication → Users**, create the email/password account you want to use for the Admin Dashboard.

Copy that user's UUID.

Then run:

```sql
insert into public.admin_users (user_id)
values ('PASTE-YOUR-SUPABASE-AUTH-USER-UUID-HERE');
```

Do not put this UUID or the admin password into your website source code.

## 3. Configure Supabase Auth URLs

In **Supabase → Authentication → URL Configuration**:

- Set the **Site URL** to your real deployed website URL.
- Add your deployed `index.html` URL to the **Redirect URLs** list.

For example, if your GitHub Pages site is:

`https://YOUR-USERNAME.github.io/YOUR-REPOSITORY/`

allow:

`https://YOUR-USERNAME.github.io/YOUR-REPOSITORY/index.html`

Use your actual URL, not the example above.

## 4. Discord OAuth

Keep the Discord provider enabled in Supabase.

Your Discord Developer Portal OAuth callback should remain:

`https://fprspgulugqfcuhgzkux.supabase.co/auth/v1/callback`

The website starts Discord login and then returns to `index.html` for the staff username/password step.

## 5. Staff accounts

After the migration is installed:

1. Sign into `admin.html` with the new Supabase admin account.
2. Open **Staff Onboarding**.
3. Create the staff username, rank, and password.
4. The password is immediately converted to a one-way hash in Supabase.
5. The plaintext password is not stored in the database, `localStorage`, or the public website source.

Because passwords are one-way hashed, the Admin Dashboard intentionally **cannot display an existing password**. If a password is lost, create a new one rather than trying to recover it.

## 6. Staff login flow

The staff flow is:

`Login with Discord → Staff username + password → Staff Dashboard`

The Discord account is authenticated, but it is **not linked to a particular staff profile**. The server simply requires a valid Discord/Supabase session before checking the separate staff credentials.

A successful staff login receives a temporary server-created session token. The token is bound to the authenticated Discord/Supabase user and expires after 12 hours.

## 7. Login history

The login history records:

- Discord username
- Discord ID
- Staff username used
- Success/failure
- Date/time

It does **not** store the staff password.

The old `staff_password` column is removed by the migration.

## 8. Important: old credentials

The old hardcoded admin password is no longer used by this version.

If that password has ever been committed to a public GitHub repository, change it and treat it as exposed. Removing it from the newest commit does not erase it from Git history.

Existing staff accounts that were stored in browser `localStorage` are not automatically imported. Recreate those staff accounts through the new Admin Dashboard so their passwords are securely hashed.

## 9. What can remain public

The website contains the Supabase **publishable** key. That key is intended for frontend use and is protected by database permissions/RLS/RPC authorization.

Never put a Supabase **service-role/secret key** in these files or in GitHub.
