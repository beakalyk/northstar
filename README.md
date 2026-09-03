# Northstar role portal

Angular frontend with a Flask + PostgreSQL authentication API. Roles are enforced by the server, not by the role selector in the browser.

## Run locally

1. Start PostgreSQL and create the `northstar` database.
2. In `server`, copy `.env.example` to `.env`, set the connection string and a strong `SECRET_KEY`, then install Python packages: `pip install -r requirements.txt`.
3. In `server`, initialize data:

   ```powershell
   flask --app app init-db
   flask --app app seed-demo
   flask --app app run --port 5050
   ```

4. In this directory, run `npm start`; then visit `http://localhost:4200`. The Angular development server proxies `/api` to Flask at port `5050`; this is required for the secure CSRF flow.

Development accounts are `administrator@northstar.io`, `manager@northstar.io`, and `member@northstar.io`; all use `ChangeMe123!`. Remove these seeded credentials in any non-development environment.

## Security model

- Password hashes use Werkzeug's current secure password hashing implementation.
- Opaque session tokens are `HttpOnly`; only SHA-256 token hashes are saved in PostgreSQL.
- CSRF protection is required for sign-in and sign-out.
- Failed logins lock an account for 15 minutes after five attempts.
- Login/logout activity is recorded in `audit_logs`.
- Set `COOKIE_SECURE=true` when deployed behind HTTPS.

This project was generated using [Angular CLI](https://github.com/angular/angular-cli) version 20.3.20.

## Development server

To start a local development server, run:

```bash
ng serve
```

Once the server is running, open your browser and navigate to `http://localhost:4200/`. The application will automatically reload whenever you modify any of the source files.

## Code scaffolding

Angular CLI includes powerful code scaffolding tools. To generate a new component, run:

```bash
ng generate component component-name
```

For a complete list of available schematics (such as `components`, `directives`, or `pipes`), run:

```bash
ng generate --help
```

## Building

To build the project run:

```bash
ng build
```

This will compile your project and store the build artifacts in the `dist/` directory. By default, the production build optimizes your application for performance and speed.

## Running unit tests

To execute unit tests with the [Karma](https://karma-runner.github.io) test runner, use the following command:

```bash
ng test
```

## Running end-to-end tests

For end-to-end (e2e) testing, run:

```bash
ng e2e
```

Angular CLI does not come with an end-to-end testing framework by default. You can choose one that suits your needs.

## Additional Resources

For more information on using the Angular CLI, including detailed command references, visit the [Angular CLI Overview and Command Reference](https://angular.dev/tools/cli) page.
