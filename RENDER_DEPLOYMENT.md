# NetSentry SOC — Render deployment

## Render service settings

This repository is a Streamlit application (not a FastAPI service). Deploy it as a
**Render Web Service** using the included `render.yaml` Blueprint:

- Runtime: Python
- Build command: `pip install -r requirements.txt`
- Start command: `streamlit run dashboard/app.py --server.address 0.0.0.0 --server.port $PORT --server.headless true`
- Health check: `/_stcore/health`
- Plan: Free

If configuring manually, use the values above and set the repository root directory
to the folder containing this file.

## Required secrets

In Render → Environment, set:

- `NETSENTRY_CLOUD_DEPLOYMENT=true`: enables cloud-safe account seeding (set automatically by the Blueprint).\n- `NETSENTRY_ADMIN_PASSWORD`: a unique, strong password for the `admin` account.
- `NETSENTRY_ANALYST_PASSWORD`: optional; if set, creates the `analyst` account.

The app seeds these accounts only when its users table is empty. If you change a
password after the first deployment, changing the environment variable alone does
not update the existing database record. On the current ephemeral SQLite deployment,
a fresh instance may reseed it, but do not rely on that for durable identity storage.

Never commit real passwords, tokens, or database URLs to GitHub.

## Important limitations of this first cloud deployment

- This is the existing Streamlit + SQLite application. It is **not yet** the planned
  FastAPI + Neon PostgreSQL architecture.
- Render Free services can sleep when idle, and the local SQLite database is on
  ephemeral storage. Data can be lost when the service restarts, redeploys, or its
  instance is replaced. Treat this as a demonstration deployment only.
- Do not upload sensitive PCAPs, production logs, personal data, or confidential
  incident evidence.
- A Render web service cannot capture packets from your laptop's Wi-Fi/Ethernet
  adapter. Use the local sensor for authorized capture, then upload sanitized
  PCAP/Zeek data for analysis where supported.
- Scapy live sniffing and privileged NIC capture are not available as a reliable
  always-on capability on the Render Free web service.
- The current password hashing implementation is salted SHA-256 and should be
  upgraded to a dedicated password-hashing algorithm before any real users or
  sensitive data are allowed. Do not treat this demo deployment as production SOC.

## Deploy

1. Push the updated files to the GitHub repository.
2. In Render, choose **New → Blueprint** and select this repository, or create a
   Web Service manually using the settings above.
3. Enter the required environment secrets when prompted.
4. Deploy and open the generated `onrender.com` URL.
