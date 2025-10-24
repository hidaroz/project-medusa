# Project Medusa

This repo is for **Project Medusa**, an academic research initiative focused on developing an **autonomous AI-driven cybersecurity agent** for educational and authorized penetration testing. The project explores how artificial intelligence can simulate adaptive offensive and defensive behaviors within **controlled, sandboxed environments**.

---

## Purpose

**Project Medusa** is built to support **cybersecurity education and research**. It helps students and researchers study real-world attack and defense dynamics safely by using AI to model adaptive threat behavior.

This project is strictly for **educational use only** and is conducted under proper supervision within **isolated systems**.

---

## Code promot


Create a comprehensive cybersecurity research project called "Project Medusa" with the following specifications:

## Project Overview
Build an autonomous AI red team agent for offensive security research that simulates advanced adversary behavior in post-exploitation scenarios. The project should consist of two main components:

### 1. Target Environment (Mock EHR Web Application)
- **Technology**: Next.js 15 with TypeScript and Tailwind CSS
- **Purpose**: High-fidelity mock Electronic Health Records system
- **Features**:
  - Professional login interface
  - Patient dashboard with statistics
  - Individual patient record pages with medical data
  - Critical allergy alert system
  - Insurance and emergency contact information
  - Dark-themed, responsive design
  - 5 realistic mock patient records with synthetic data
- **Security**: No real backend logic, all data is mocked and static
- **Deployment**: GitHub Pages for demonstration

### 2. Command & Control CLI (Python)
- **Framework**: Python with argparse for command-line interface
- **AI Integration**: Google Gemini API for intelligent decision making
- **Architecture**: Modular design with separate components
- **Core Commands**:
  - `init` - Initialize kill box environment
  - `deploy` - Deploy AI agent with strategic objective
  - `monitor` - Monitor agent operations
  - `report` - Generate operation reports
  - `assess` - Run AI security assessment
  - `status` - Check system status

### AI Agent Features
- **Gemini API Integration**: Use Google Gemini API for intelligent decision making
- **Access Level Detection**: Detect current system privileges (admin/root/basic_user)
- **Data Classification**: Classify discovered data as medical_records, financial_data, credentials, personal_info, or system_data
- **Confidence Scoring**: Provide confidence scores (0.0-1.0) for classifications
- **Performance Targets**: Set performance targets based on access level

### Gemini API Integration
- **Environment Variable**: Use GEMINI_API_KEY environment variable
- **Model**: Use gemini-2.5-flash model
- **Analysis Prompt**: 

## Current Focus

- Refining the *Detect → Assess → Adapt* logic loop  
- Adding a *Context-Persistence Layer* to improve learning and consistency  
- Expanding *Multi-Layered Sensing* for network and host-level awareness  
- Conducting sandboxed simulations for validation  

---

## Ethical Disclaimer

**Project Medusa** is intended for **educational and authorized research only**.  
Do **not** use this code or related techniques on live systems or networks.  
For full details, see [`/project-medusa/README.md`](./project-medusa/README.md).

---

## Team

**Developed by:** Hidar Elhassan, Lawrence Xu, Brian Yuan

**Advisor:** Frank Martinez, University of Washington 

**Course:** INFO 492 – Capstone Project  

---



