# Northstar Flask API

This API uses PostgreSQL and opaque, database-backed sessions. The session identifier is held in a `HttpOnly` cookie; only its SHA-256 hash is stored in the database. State-changing requests require the Angular-compatible `XSRF-TOKEN` / `X-XSRF-TOKEN` pair.

## Local setup

1. Create a PostgreSQL database named `northstar` and a matching application user.
2. Copy `.env.example` to `.env`, then set a long random `SECRET_KEY` and your `DATABASE_URL`.
3. Create and activate a virtual environment, then install dependencies: `pip install -r requirements.txt`.
4. Run `flask --app app init-db` then `flask --app app seed-demo`.
5. Run `flask --app app run --port 5050`.

For local preview, sign in with `administrator@northstar.io`, `manager@northstar.io`, or `member@northstar.io`, all using `ChangeMe123!`. Seed data is development-only; remove the seed command from production workflows.

## Production notes

- Set `COOKIE_SECURE=true` behind HTTPS and rotate `SECRET_KEY` with a managed secret store.
- Put the API behind a reverse proxy, enforce TLS, and add a shared rate-limit store such as Redis.
- Use Alembic/Flask-Migrate migration revisions rather than `init-db` for schema changes after first deployment.
