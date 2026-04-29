# CodeShield AI — Backend

FastAPI backend for scanning GitHub repositories for security vulnerabilities.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/scan` | Scan a GitHub repository |
| GET | `/api/docs` | Swagger UI |

## Example

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/OWASP/WebGoat"}'
```
