# Project Medusa - Target Environment (Mock EHR Application)

## ⚠️ Important: This is ONE HALF of Project Medusa

This repository contains the **TARGET ENVIRONMENT** - a high-fidelity mock Electronic Health Record (EHR) web application. The other half, the **Medusa CLI** (Command & Control interface), is located in a separate directory.

## Overview

This Next.js application serves as a realistic-looking target for the Medusa AI adversary simulation. It provides a professional, tangible interface that demonstrates what the AI agent is attempting to compromise during security research operations.

### Key Characteristics

- **High-Fidelity Mock**: Professional UI that looks like a real EHR system
- **No Real Backend**: All data is static/mocked - no database, no real authentication
- **Presentation-Ready**: Clean, modern interface suitable for demonstrations
- **Contained Environment**: Operates within a Docker kill box for security

## Technology Stack

- **Framework**: Next.js 15 (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **Runtime**: Node.js

## Features

### 1. User Authentication
Professional login screen with:
- Username/password interface
- Mock authentication (any credentials work)
- Corporate branding and styling

### 2. Patient Dashboard
Central command center showing:
- Complete patient list
- Critical statistics
- Quick access to patient records
- Allergy alerts and status indicators

### 3. Detailed Patient Records
Individual patient pages featuring:
- Complete demographic information
- **Critical allergy alerts** with visual warnings
- Current medications
- Medical conditions
- Insurance information
- Emergency contacts
- Appointment history

### 4. Professional UI/UX
- Dark-themed, modern interface
- Responsive design
- Healthcare-appropriate color scheme
- Clean typography and spacing

## Project Structure

```
medusa-webapp/
├── src/
│   ├── app/
│   │   ├── page.tsx              # Login page
│   │   ├── dashboard/
│   │   │   └── page.tsx          # Patient dashboard
│   │   └── patient/
│   │       └── [id]/
│   │           └── page.tsx      # Individual patient records
│   └── lib/
│       └── patients.ts            # Mock patient data
├── public/                        # Static assets
└── README.md
```

## Getting Started

### Installation

```bash
npm install
```

### Development Server

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Login

Use **any username and password** to access the system. For example:
- Username: `admin`
- Password: `password`

## Mock Data

The application includes 5 mock patient records with realistic:
- Patient demographics
- Medical histories
- Current medications
- Allergies (highlighted with critical alerts)
- Medical conditions
- Insurance information

All data is stored in `/src/lib/patients.ts` and served statically from the frontend.

## The Two-Sided Project

### This Application (Target)
- **Purpose**: Realistic target environment
- **Location**: `devprojects/medusa-webapp/`
- **Technology**: Next.js web application
- **Interaction**: Passive target for agent operations

### The Medusa CLI (Operator)
- **Purpose**: AI agent command & control
- **Location**: `devprojects/medusa-cli/`
- **Technology**: CLI application (separate repository)
- **Interaction**: Active offensive operations

## Use Cases

1. **Security Research**: Test AI-driven offensive techniques
2. **Red Team Training**: Demonstrate post-exploitation scenarios
3. **Presentations**: Show realistic adversarial AI capabilities
4. **Defense Development**: Understand AI-powered threats

## Security Note

⚠️ **This is a non-functional mock application**
- No real authentication mechanisms
- No actual database or backend
- No real patient data
- Designed for contained testing environments only

## Development Roadmap

- [x] Basic authentication UI
- [x] Patient dashboard
- [x] Individual patient records
- [x] Allergy alert system
- [ ] Docker containerization
- [ ] Additional mock features as needed
- [ ] Enhanced realism for demonstrations

## Contributing

This is an offensive security research project. Contributions should maintain the high-fidelity mock nature while keeping the application simple and presentation-ready.

---

**Project Medusa** - AI Adversary Simulation Research Initiative
