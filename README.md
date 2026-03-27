## 🚀 Quick Start (Plug-and-Play)
To instantly download and run the pre-built application from Docker Hub:
`docker compose up -d`

## 🛠️ Build from Source (For Developers)
If you want to modify the source code (e.g., editing the FastAPI backend or the HTML frontend), you can force Docker to build the image locally using the provided development compose file:
`docker compose -f docker-compose.dev.yml up -d --build`

## The default credential for sonar-qube 

```text
Username: admin
Password: Sonar_Internal_Auth_123!