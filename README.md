# SiteAudit Pro

AI-Powered Website Security, UI/UX, and Performance Analysis Tool

## Quick Start

```bash
# 1. Clone and navigate
git clone <repository-url>
cd website-analyzer

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env and add your GROQ_API_KEY

# 5. Run the application
python backend/app.py

# 6. Open in browser
# http://127.0.0.1:5002
```

## Documentation

- **[Full Documentation](docs/README.md)** - Complete guide with features, API reference, and troubleshooting

## Project Structure

```
├── backend/           # Flask API and analysis engine
│   ├── app.py
│   └── analyzer.py
├── frontend/          # HTML templates and CSS
│   ├── templates/
│   └── static/
├── docs/              # Documentation
├── venv/              # Python virtual environment
├── .env               # Environment variables
├── .gitignore         # Git ignore rules
└── requirements.txt   # Python dependencies
```

## Tech Stack

- **Backend**: Python, Flask
- **Frontend**: HTML5, CSS3, JavaScript
- **AI Engine**: Groq API (Llama 3.3 70B Versatile)
- **Parsing**: BeautifulSoup4, Requests

## Features

- 20+ Security checks (HTTPS, headers, cookies, XSS, CSRF, SQLi, XXE, SSRF)
- 15+ UI/UX checks (viewport, alt text, headings, accessibility)
- 18+ Performance checks (compression, caching, DOM, images, fonts)
- AI-powered structured analysis with implementation roadmap
- Professional dark-themed UI with real-time loading states
- Accurate issue counting and scoring

## Requirements

- Python 3.8+
- Groq API key ([Get one free](https://console.groq.com))

## License

MIT
