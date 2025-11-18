


Start/Shutdown 
#Navigate to your project directory Make sure you’re in the folder that contains your docker-compose.yml (created during setup):
 
cd ~
 
#Check Docker service status
 
#Ensure Docker is running and the compose plugin is available:
 
sudo systemctl start docker docker-compose version
 
#If it prints a version (e.g., Docker Compose version v2.29.x), you’re good.
 
#Start the containers
 
#Bring up both the Ollama and Atlantis webservice containers in the background:
 
docker-compose up -d
 
#Verify container status
 
#Confirm both containers are running and healthy:
 
docker-compose ps




You should see output similar to:

NAME IMAGE STATUS PORTS ollama ollama/ollama:latest Up (healthy) 127.0.0.1:11434->11434/tcp atlantis-webservice atlantis-webservice Up (healthy) 127.0.0.1:8000->8000/tcp

If either shows (unhealthy) or (exited), check logs:



docker-compose logs --tail=100 ollama docker-compose logs --tail=100 atlantis-webservice
 
#Stop containers (when done)
 
docker-compose down
 
#This cleanly shuts down both services and releases ports 8000 and 11434.


Simple File Analysis 
To run a single file (VulnerableApp.Java example)
Put VulnerableApp.java at ~/VulnerableApp.java.

Ensure webservice + ollama are up (docker-compose up -d and model pulled).

Run:

chmod +x ~/crs_file_vuln.sh
SHOW_LOGS=1 CHUNK_BYTES=6000 MAX_CHUNKS=8 LLM_MAX_TOKENS=256 \
~/crs_file_vuln.sh ~/VulnerableApp.java \
"hard-coded secrets, weak crypto, auth & input validation" | tee ~/vuln_findings_file.json


Inspect ~/vuln_findings_file.json — it will be pretty JSON (indented).

To run on a git repo (Accumulo example)
Ensure webservice + ollama are up and model present.

Run:

SHOW_LOGS=1 \
INCLUDE_PATHS="shell/src/main/java/org/apache/accumulo/shell shell/src/test/java" \
~/crs_repo_vuln.sh ~/accumulo \
"auth paths, command injection, secrets in config or CLI" \
| tee ~/vuln_findings_accumulo_shell.json


Inspect the pretty JSON in the output file.

Tips / troubleshooting
If the output still isn’t valid JSON: the model likely returned prose instead of JSON. Re-run with smaller CHUNK_BYTES / fewer MAX_CHUNKS to reduce prompt size, or adjust the system prompt to strictly enforce Return ONLY a JSON array.
If you get timeouts or 500s: reduce context size (MAX_TOTAL_BYTES), reduce CHUNK_BYTES, reduce MAX_CHUNKS, or lower LLM_MAX_TOKENS.
To tune ETA accuracy, calibrate ETA_BYTES_PER_SEC_HINT and ETA_TOKENS_PER_SEC_HINT for your machine.
Save outputs with tee so you have a persisted record.
CAPI Web App: Competition Portal Setup Guide
1. Prerequisites
Before you begin, install or verify the following are available on your system:

Requirement    

Git    ≥ 2.30    For cloning repositories
Docker    ≥ 24.0    Required to run containers
Docker Compose    ≥ 2.20    Compose plugin for Docker (check with docker compose version)
Ports    8001, 8080, 8082, 9000, 11435    Ensure they’re open on host
Disk Space    ≥ 10 GB    For images, models, logs
2. Clone the Repository
git clone https://github.com/asavalo/atlantis.git
cd atlantis

The structure will look roughly like this:

atlantis/
├── Phase_2/
│   ├── stack/              # Docker Compose stack (Atlantis + CAPI + LLM + Ollama)
│   ├── capi/               # Competition API backend (FastAPI)
│   ├── webui/              # Optional web portal (React/Vite + Nginx)
│   ├── setup.sh            # Helper for scaffolding web UI
│   ├── compose.yaml        # Main compose definition
│   └── capi-webui.override.yaml (optional)

3. Install Docker Compose Plugin


#If not installed:
 
sudo apt install docker-ce docker-compose-plugin -y
 
 
#Test it:
 
docker compose version
4. Start the Core Services
This includes:

Atlantis (AI vulnerability finder)

CAPI (Competition API)

LLM Gateway

Ollama (model host)



#Run from the stack directory:
 
cd Phase_2/stack
docker compose up -d --build
 
 
#You should see containers start:
 
docker compose ps

Expected services:

stack-atlantis-1      Up      9000/tcp
stack-capi-1          Up      8001/tcp
stack-llm-gateway-1   Up      8080/tcp
stack-ollama-1        Up      11435/tcp

5. Load an LLM Model (Ollama)
Atlantis uses the LLM gateway → Ollama → Model chain.





#Pull the model:
 
docker exec -it stack-ollama-1 ollama pull llama3:8b
 
 
#Confirm it’s available:
 
docker exec -it stack-ollama-1 ollama list

You should see:

llama3:8b   8.0B parameters   ready

6. Verify API Connectivity
#Health checks
curl http://localhost:8001/health/   # cAPI
curl http://localhost:8080/health/   # LLM gateway
curl http://localhost:9000/health/   # Atlantis

Expected:

{"status":"ok"}

7. (Optional) Build the Web UI
The competition portal provides a dark, military-style React front end for CAPI task submission.



#Build and run:
cd ../webui
docker build -t capi-webui:dark-ops \
  --build-arg VITE_CAPI_URL=http://localhost:8001 \
  .
docker run -d --name capi-webui -p 8082:80 capi-webui:dark-ops

Then visit:
http://localhost:8082

Web UI Features:
Check API health
Basic authentication
Upload file or GitHub repo for scanning (/submission/vds or /submission/gp)
Displays submission UUIDs and API responses
8. Authentication
The CAPI endpoints use HTTP Basic Auth.

#You can pass credentials in the UI or directly with curl:
 
curl -u user:password -X POST http://localhost:8001/submission/vds/ -d '{"data":"..."}'
 
 
#To modify credentials, edit:
 
#Phase_2/capi/env
 
 
#and restart:
 
docker compose restart capi




9. Submitting Tasks (via curl or UI)
Example — upload a vulnerability dataset (VD):



curl -u user:password -X POST http://localhost:8001/submission/vds/ \
  -H 'Content-Type: application/json' \
  -d '{"cpv_uuid":"f20a55db-7162-4b2e-b301-1e965a3c8757","data":"<BASE64_STRING>"}'

Response:

{
  "vd_uuid": "6bce1234-1234-4567-89ab-abcdef012345",
  "status": "FeedbackStatus.ACCEPTED"
}



#You can check status:
 
curl -u user:password http://localhost:8001/submission/vds/<UUID>
10. Stopping Everything


#To gracefully stop and clean up:
 
docker compose down
docker rm -f capi-webui
Summary of Key URLs

Atlantis Backend    http://localhost:9000 Vulnerability Finder
CAPI (Competition API)    http://localhost:8001 Submission & Task API
LLM Gateway    http://localhost:8080 Chat/Completion Bridge
Ollama Model Host    http://localhost:11435 Local Model Service
Web UI (Portal)    http://localhost:8082 User Interface
Tips
If you get a CORS error in the web UI:
edit Phase_2/capi/competition_api/main.py and ensure:



from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8082"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
#then restart:
 
docker compose restart capi
