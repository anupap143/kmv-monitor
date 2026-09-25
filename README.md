# KMV Network Monitor on Kubernetes (Jenkins + Docker + kind)

Deploys the KMV Network Monitor (Flask app + PostgreSQL) to the kind cluster `mycluster` on test-pgsql (172.16.30.124), using the same Jenkins setup as practice-app.

All files are in one folder, so you can upload them to GitHub with drag and drop. No subfolders are needed.

| File | Purpose |
|---|---|
| `isp-monitor.py`, `dashboard.html`, `login.html`, `reset-password.html` | The application |
| `requirements.txt` | Python packages (versions pinned and tested) |
| `Dockerfile`, `.dockerignore` | Builds the image |
| `Jenkinsfile` | The pipeline |
| `k8s-namespace.yaml` | Namespace `kmv-monitor` |
| `k8s-postgres.yaml` | PostgreSQL 15 with a 2 GiB volume |
| `k8s-app.yaml` | Settings (ConfigMap), a 1 GiB volume for files, the app, and its Service |
| `docker-compose.yml`, `.env.example` | For running locally with Docker Compose, as before |

Never upload `.env` / `_env` to GitHub. Passwords go into a Kubernetes Secret (step 1).

---

## Step 1: Create the Secret (once, on the server)

```bash
su - psadmin
kubectl create namespace kmv-monitor
kubectl -n kmv-monitor create secret generic kmv-monitor-secrets \
  --from-literal=POSTGRES_PASSWORD="$(openssl rand -hex 16)" \
  --from-literal=FLASK_SECRET_KEY="$(openssl rand -hex 32)" \
  --from-literal=SMTP_PASSWORD=""
kubectl -n kmv-monitor get secret kmv-monitor-secrets
```

Random passwords are generated for you; you never need to type them. Don't change `POSTGRES_PASSWORD` later: PostgreSQL only reads it when the database is first created.

## Step 2: Put the code on GitHub

Create a new repository (for example `kmv-network-monitor`), click **Add file → Upload files**, drag in **all** the files, and commit. Check that `.dockerignore` and `.gitignore` are there too.

If you have the `static` folder with images (such as `network-monitor-plain.svg` for the login background), upload the images as well. They can be in a `static` folder or loose next to the other files; the Dockerfile handles both.

## Step 3: Create the Jenkins job

**New Item** → `kmv-monitor` → **Pipeline** → OK. In the **Pipeline** section:

| Field | Value |
|---|---|
| Definition | Pipeline script from SCM |
| SCM | Git |
| Repository URL | your new repo URL |
| Branch Specifier | `*/main` |
| Script Path | `Jenkinsfile` |

**Save** → **Build Now**. Stages: Check tools → Check secret → Build image → Load image into kind → Deploy database → Deploy app → Smoke test.

## Step 4: Open the app from Windows

```powershell
ssh -L 8083:localhost:8084 psadmin@172.16.30.124 "/usr/local/bin/kubectl -n kmv-monitor port-forward svc/kmv-monitor 8084:80"
```

Keep the window open and browse to **http://localhost:8083**.

The first login is `admin` / `admin123`. **Change this password straight away** (profile → change password).

After each new build, press Ctrl+C and run the command again, because the pod is replaced.

## Step 5: Check that pinging works from Kubernetes

```bash
kubectl -n kmv-monitor exec deploy/kmv-monitor -- ping -c 2 115.108.34.237
```

If this fails but `ping 115.108.34.237` works on the server itself, send the output for troubleshooting.

---

## Mail alerts

Non-secret settings are in `k8s-app.yaml` (ConfigMap): `SMTP_USER`, `SMTP_FROM`, `MAIL_ALERTS_ENABLED`, `MAIL_ALERT_RECIPIENTS`, etc. Edit them on GitHub and rebuild.

Set the SMTP password in the Secret (not in Git):

```bash
kubectl -n kmv-monitor patch secret kmv-monitor-secrets \
  -p "{\"stringData\":{\"SMTP_PASSWORD\":\"YOUR-APP-PASSWORD\"}}"
kubectl -n kmv-monitor rollout restart deployment/kmv-monitor
```

Mail settings saved in the dashboard's Mail Settings page are stored by the app and take priority over these values.

## Moving existing data (optional)

If you already run this app with Docker Compose and want to keep its users, zones, engineers and sites, copy its `data/portal_config.json` to the server and load it **before the first build**, or at any time followed by a restart:

```bash
kubectl -n kmv-monitor cp portal_config.json $(kubectl -n kmv-monitor get pod -l app=kmv-monitor -o name | cut -d/ -f2):/app/data/portal_config.json
```

The app reads the database first. On a new, empty database it imports `portal_config.json` and saves it to PostgreSQL.

## Changes made to the original project

| Change | Why |
|---|---|
| New `/healthz` endpoint (no login, not rate-limited) | Kubernetes health checks. Using `/login` would count against the rate limit and get the pod restarted |
| `RATE_LIMIT_DEFAULT` environment variable (default unchanged: `200 per day;50 per hour`) | The dashboard refreshes every 10 s, about 360 requests an hour, so the old limit blocks users with HTTP 429 after roughly 8 minutes. Behind port-forward or an Ingress, all users share one IP address. Kubernetes sets 2000 per hour |
| `FLASK_USE_RELOADER` environment variable (default unchanged: `true`) | The reloader runs the script twice, which starts two ping workers and sends every alert mail twice. Kubernetes turns it off |
| Dockerfile: Python 3.12 (was 3.9, which no longer gets security fixes), pinned package versions, Unix line endings | Reproducible, supported builds |
| Dockerfile: `sites_data.json` and `future_sites_data.json` are links into `/app/data` | The app writes these next to `isp-monitor.py`, so they were lost whenever the container was recreated. Now they are on the volume |
| `.dockerignore` | Keeps `.env` (with the SMTP password) and local data out of the image |

The app keeps its state in memory and runs one ping loop, so it must run as **1 replica** (set in `k8s-app.yaml`).

## Useful commands

```bash
kubectl -n kmv-monitor get pods,pvc
kubectl -n kmv-monitor logs deploy/kmv-monitor --tail=50
kubectl -n kmv-monitor exec -it statefulset/kmv-db -- psql -U kmv_admin -d kmv_network_db -c "select state_key, updated_at from portal_state;"
kubectl delete namespace kmv-monitor     # removes everything, including the database
```
