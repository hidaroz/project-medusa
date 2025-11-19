# Deploying Medusa to Fly.io

Medusa is configured for deployment on [Fly.io](https://fly.io).

## Prerequisites

1.  **Fly.io Account:** Sign up at [fly.io](https://fly.io).
2.  **Fly CLI:** Install the Fly CLI:
    *   **macOS (Brew):** `brew install flyctl`
    *   **Windows (Powershell):** `pwsh -Command "iwr https://fly.io/install.ps1 -useb | iex"`
    *   **Linux/Other:** `curl -L https://fly.io/install.sh | sh`
3.  **Login:** Run `fly auth login` to authorize your CLI.

## Setup

Since app names on Fly.io must be globally unique, you need to generate your own configuration files or update the existing ones with unique names.

1.  **Update App Names:**
    *   Open `fly.api.toml` and change `app = "medusa-api-prod"` to something unique (e.g., `medusa-api-yourname`).
    *   Open `fly.webapp.toml` and change `app = "medusa-webapp-prod"` to something unique (e.g., `medusa-webapp-yourname`).

2.  **Initialize Apps (First Time Only):**
    *   If these apps don't exist yet in your Fly.io dashboard, you might need to launch them to register the names:
        ```bash
        fly launch --config fly.api.toml --no-deploy --copy-config --name <your-api-app-name> --region sjc
        fly launch --config fly.webapp.toml --no-deploy --copy-config --name <your-webapp-app-name> --region sjc
        ```

## Deployment Steps

### 1. Deploy Backend API

Deploy the API first so we can get its URL for the frontend.

```bash
fly deploy --config fly.api.toml
```

**Get the API URL:**
After deployment, your API will be available at `https://<your-api-app-name>.fly.dev`.

### 2. Deploy Frontend Webapp

Now deploy the frontend, setting the `MEDUSA_API_URL` secret to your backend's URL.

```bash
# Set the API URL secret (replace with your actual API URL)
fly secrets set MEDUSA_API_URL=https://<your-api-app-name>.fly.dev --config fly.webapp.toml

# Deploy the webapp
fly deploy --config fly.webapp.toml
```

## Accessing Medusa

Your Medusa Dashboard is now live at:
`https://<your-webapp-app-name>.fly.dev`

## Important Notes

*   **Persistence:** Like Render's free tier, Fly.io machines are ephemeral by default. Data stored on the local filesystem will be lost if the machine restarts. For persistent data, attach a Fly Volume:
    ```bash
    fly volumes create medusa_data --region sjc --size 1 --config fly.api.toml
    ```
    Then update `fly.api.toml` to mount this volume.
*   **Scale to Zero:** The configuration is set to `auto_stop_machines = true`. This means your app will sleep when not in use to save credits, and wake up automatically when accessed (cold start delay ~3-5s).

