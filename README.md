Without ADMIN_PASSWORD, the first visit to the site shows a setup page where the new owner chooses a username and password. After that the page is closed for good. Open the link right after deploying, or set SETUP_KEY so only people who know the key can reach the setup page. To reset a forgotten password, set ADMIN_PASSWORD and redeploy.
Persistence
Mount a volume at /data, otherwise users and the password reset on every deploy.
Endpoints
/admin panel, /login, /sub/<token> subscription, /healthz health check.