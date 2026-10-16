# NetSec Agent

NetSec Agent is a Python project for authorized network assessments. It uses Groq, LangGraph, MCP, and Nmap to run basic scans and help explain the results through a Streamlit interface.

## Features

- Host discovery and TCP port scanning with Nmap
- Service-version detection
- Discovery of approved private IPv4 subnets, limited to 256 addresses
- Basic risk scoring based on detected open ports
- A Streamlit interface for interacting with the agent

## Setup

You need Python 3.12, Nmap, and a Groq API key.

Clone the repository and install the dependencies:

```powershell
git clone https://github.com/TheRootBaba/NetSEc-agent.git
cd NetSEc-agent
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Copy `.env.example` to `.env` and add your Groq API key. Keep `.env` private.

## Run

```powershell
python -m streamlit run src/netsec_agent/app.py --server.address 127.0.0.1
```

## Tests

```powershell
python -m pytest -q
python -m ruff check .
```

## Notes

Only scan systems and networks you have permission to assess. Risk scores are estimates, not proof of vulnerabilities. TShark packet analysis and Wazuh integration are not implemented yet.

See `LICENSE` for license information.

## Demo

[Watch the working agent demo](https://github.com/user-attachments/assets/870edb32-20fc-4f8a-aaf3-4c7679b5109c)
