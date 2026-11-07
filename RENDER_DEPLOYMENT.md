# NetWatch SOC — Cloud Deployment & Service Guide

## Overview

This repository provides two deployment targets:
1. **GitHub Pages WebApp (Client-Side)**: [https://noobkushal.github.io/C2/](https://noobkushal.github.io/C2/)
2. **Render Python Cloud Service**: Host the native Streamlit + SQLite SOC dashboard on Render Free tier.
3. **Localhost Application**: [http://localhost:8501/](http://localhost:8501/) (Run via `run_localhost.bat`).

---

## Render Service Settings

Deploy as a **Render Web Service** using the included `render.yaml` Blueprint or manual configuration:

- **Repository**: [https://github.com/noobkushal/C2](https://github.com/noobkushal/C2)
- **Runtime**: Python
- **Build command**: `pip install -r requirements.txt`
- **Start command**: `streamlit run dashboard/app.py --server.address 0.0.0.0 --server.port $PORT --server.headless true`
- **Health check path**: `/_stcore/health`
- **Plan**: Free

---

## Required Environment Secrets

In Render → Service → Environment, set:

- `NETSENTRY_CLOUD_DEPLOYMENT=true`: Enables cloud-safe account seeding (set automatically by the Blueprint).
- `NETSENTRY_ADMIN_PASSWORD`: A unique, strong password for the `admin` account.
- `NETSENTRY_ANALYST_PASSWORD`: (Optional) Password for the `analyst` account.

The app seeds these accounts only when its users table is empty. Never commit real passwords, tokens, or database URLs to GitHub.

---

## Architecture Boundaries on Cloud Hosting

- **Cloud Packet Capture Limitations**: A cloud service on Render runs inside a container and cannot sniff packets from your physical laptop's Wi-Fi or Ethernet card.
- **Hardware Sniffing**: Use the local sensor (`setup_live_sniffer.bat` or `start_soc.bat`) for physical NIC capture on Windows, then upload sanitized PCAP files for cloud analysis.
- **Client-Side Alternative**: Use the [GitHub Pages WebApp](https://noobkushal.github.io/C2/) for instant in-browser Wireshark PCAP analysis, C2 regularity detection, and report generation with zero installations.

---

## Deployment Steps

1. Push your updated files to the GitHub repository: `https://github.com/noobkushal/C2`.
2. In Render, select **New → Blueprint** and link the `noobkushal/C2` repository.
3. Supply the required environment passwords when prompted.
4. Click **Apply** to deploy the service.
