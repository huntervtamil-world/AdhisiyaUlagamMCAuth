# AdhisiyaUlagam®MC Auth

A source project for a Paper server with Geyser/Floodgate. All players must register and log in. The admin-approved premium list only adds a display label; it does **not** bypass login.

## Commands
- `/register <password> <confirmPassword>` — create an account
- `/login <password>` — authenticate
- `/changepassword <oldPassword> <newPassword>` — change your password
- `/authadmin premium add <player>` — add a premium label
- `/authadmin premium remove <player>` — remove a premium label
- `/authadmin name set <player> <display name>` — set a custom display name
- `/authadmin name reset <player>` — restore the account name
- `/authadmin reload` — reload config

## Permissions
- `adhisiyaauth.admin` — admin commands (default OP)
- `adhisiyaauth.bypass` — explicit authentication bypass (default false; avoid granting casually)

## Build
1. Install JDK 21 and Maven 3.9+.
2. Open a terminal in this folder.
3. Run `mvn clean package`.
4. Copy `target/AdhisiyaUlagamMCAuth.jar` into your server's `plugins/` folder.
5. Restart the server (do not use `/reload`).

This project compiles against Paper API 1.21.4 as a stable API baseline. Test on your exact Paper 26.2 build before production; if the build's API or Java requirement differs, update the Paper API dependency and JDK release in `pom.xml` to match your server.

## Geyser/Floodgate notes
This plugin uses Bukkit player UUIDs and does not need a direct Floodgate dependency. Test Java and Bedrock joins on your exact Geyser/Floodgate configuration. For offline-mode servers, ensure the server is correctly protected by a proxy/firewall and Floodgate is configured securely.

## Security notes
- Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes, not plaintext.
- Password length is bounded; failed login attempts are limited.
- Account data is keyed by UUID, not the visible username.
- Back up `plugins/AdhisiyaUlagamMCAuth/` securely.
- Never give anyone the server console, database files, or `adhisiyaauth.bypass` permission unless trusted.
- Because every player must register and log in, the premium list is a label only. It is not proof of ownership of an official Minecraft account.
- Chat events and plugin behavior can differ between server versions; compile and test against the exact target API before deploying.


## Build the JAR in GitHub Actions
This project includes `.github/workflows/build.yml`. Push the extracted project to a GitHub repository, open **Actions**, select **Build AdhisiyaUlagamMCAuth**, and run the workflow (or push to `main`). When it succeeds, open the workflow run and download the `AdhisiyaUlagamMCAuth` artifact. It contains `AdhisiyaUlagamMCAuth.jar`.

The build uses Paper API 1.21.4 as the compile-time API baseline and Java 21 bytecode, which can run on newer Java runtimes. It has not been tested against your exact Paper 26.2 server; test on a backup/test server first.
