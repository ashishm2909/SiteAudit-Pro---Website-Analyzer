# SiteAudit Pro - Setup Guide

## Prerequisites

- Python 3.8 or higher
- pip package manager
- Groq API key ([Sign up free](https://console.groq.com))
- Git (for cloning)

## Step 1: Clone the Repository

```bash
git clone <your-repository-url>
cd website-analyzer
```

## Step 2: Create Virtual Environment

### On macOS/Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

### On Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

You should see `(venv)` in your terminal prompt.

## Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- Flask 2.3.3 - Web framework
- requests 2.31.0 - HTTP library
- beautifulsoup4 4.12.2 - HTML parsing
- groq 1.5.0 - Groq AI SDK
- python-dotenv 1.0.0 - Environment variables

## Step 4: Get Groq API Key

1. Go to [console.groq.com](https://console.groq.com)
2. Sign up or log in with your account
3. Click on "API Keys" in the left sidebar
4. Click "Create API Key"
5. Give it a name (e.g., "SiteAudit Pro")
6. Copy the generated key immediately (it won't be shown again)

## Step 5: Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your values:

```bash
# .env file
GROQ_API_KEY=gsk_your_actual_groq_api_key_here
SECRET_KEY=your_random_secret_key_here
```

### Generating a Secret Key

You can generate a secure secret key using Python:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Copy the output and paste it as the `SECRET_KEY` value.

## Step 6: Run the Application

```bash
# Make sure you're in the project root and venv is activated
python backend/app.py
```

You should see:
```
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on http://127.0.0.1:5002
```

## Step 7: Open in Browser

Navigate to:
```
http://127.0.0.1:5002
```

You should see the SiteAudit Pro homepage.

## Usage

1. Enter a website URL (e.g., `https://example.com`)
2. Click "Analyze Website"
3. Wait for analysis to complete (30-60 seconds)
4. Review:
   - Overall scores (Security, UI/UX, Performance)
   - AI-powered insights
   - Detailed findings by category
   - Action plan with recommendations

## Troubleshooting

### Port Already in Use

If you see `Address already in use`, another process is using port 5002.

**On macOS/Linux:**
```bash
# Find and kill the process
lsof -ti:5002 | xargs kill -9
```

**Or change the port in `backend/app.py`:**
```python
app.run(debug=True, host='0.0.0.0', port=5003)
```

### Module Not Found

Make sure you're in the virtual environment:
```bash
source venv/bin/activate  # macOS/Linux
# OR
venv\Scripts\activate     # Windows
```

Reinstall dependencies:
```bash
pip install -r requirements.txt
```

### AI Analysis Unavailable

This means either:
1. Invalid Groq API key - check `.env` file
2. Groq API is down - check [status.groq.com](https://status.groq.com)
3. Rate limit exceeded - wait a few minutes and try again

### SSL Certificate Errors

The tool uses `verify=False` for sites with invalid SSL certificates. This is intentional for testing purposes. You may see InsecureRequestWarning in logs, which is normal.

## Development

### Project Structure

```
backend/
├── app.py              # Flask routes and configuration
└── analyzer.py         # Core analysis engine with 50+ checks

frontend/
├── templates/
│   └── index.html      # Single-page application UI
└── static/
    └── style.css       # Dark theme professional styling

docs/
└── README.md           # This file

root/
├── .env                # Your environment variables (git-ignored)
├── .env.example        # Environment template
├── .gitignore          # Git ignore rules
├── requirements.txt    # Python dependencies
└── README.md           # Project overview
```

### Adding New Checks

1. Open `backend/analyzer.py`
2. Find the appropriate analysis method:
   - `_analyze_security()` - for security checks
   - `_analyze_ui()` - for UI/UX checks
   - `_analyze_performance()` - for performance checks
3. Add your check following the pattern:
```python
if condition_met:
    issues.append({
        'type': 'Category',
        'severity': 'high|medium|low',
        'title': 'Issue Title',
        'description': 'Detailed description',
        'fix': 'How to fix this issue'
    })
```

### Customizing the UI

Edit `frontend/static/style.css` for styling changes.
Edit `frontend/templates/index.html` for layout changes.

### AI Prompt Customization

Edit the `_ai_analysis()` method in `backend/analyzer.py` to customize:
- Analysis format
- Prompt structure
- Output sections
- Token limits

## Production Deployment

### Using Gunicorn

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5002 backend.app:app
```

### Using Docker

Create a `Dockerfile`:
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "backend/app.py"]
```

Build and run:
```bash
docker build -t siteaudit-pro .
docker run -p 5002:5002 siteaudit-pro
```

### Environment Variables in Production

Never commit `.env` to version control. Use:
- Docker secrets
- Kubernetes secrets
- Environment variables in hosting platform
- CI/CD secret management

## Security Notes

- This tool analyzes public websites - ensure you have permission to scan targets
- The `.env` file contains sensitive data and is git-ignored
- Never expose your Groq API key in client-side code
- Use HTTPS in production
- Implement rate limiting for the `/analyze` endpoint
- Add authentication if deploying publicly

## Performance Tips

- Analysis typically takes 30-60 seconds depending on target site
- Groq API calls are limited by your plan
- Consider caching results for repeated analyses
- Use CDN for static assets in production

## Support

For issues or questions:
1. Check this documentation
2. Review the code comments
3. Open an issue on GitHub

## License

MIT License - see LICENSE file for details
