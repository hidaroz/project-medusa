# Deploying Medusa to Render

Medusa is configured for easy deployment on [Render](https://render.com) using Infrastructure as Code (Blueprints).

## Prerequisites

1.  A Render account.
2.  This repository pushed to GitHub or GitLab.

## Deployment Steps

1.  **Create a New Blueprint:**
    *   Go to your Render Dashboard.
    *   Click **New +** -> **Blueprint**.
    *   Connect your repository.

2.  **Configure:**
    *   Render will automatically detect the `render.yaml` file.
    *   Give your Blueprint a name (e.g., `medusa-stack`).
    *   Click **Apply**.

3.  **Wait for Deployment:**
    *   Render will build and deploy two services:
        *   `medusa-api`: The Python backend API.
        *   `medusa-webapp`: The Next.js frontend dashboard.
    *   The frontend will automatically be configured with the backend's URL.

## Accessing Medusa

Once deployed, click on the `medusa-webapp` service in your Render dashboard to find its URL (e.g., `https://medusa-webapp-xxxx.onrender.com`).

## Important Notes

*   **Free Tier:** This configuration uses the Free plan by default. Free instances spin down after inactivity, which may cause a delay on the first request.
*   **Persistence:** The Free plan does not support persistent disks. Logs and generated reports stored in `~/.medusa` will be lost if the API service restarts. For production use, upgrade the `medusa-api` service to a paid plan and add a Disk.

