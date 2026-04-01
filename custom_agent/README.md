# Flask LLM Providers API

Simple CRUD API for managing LLM providers.

## Project Structure

```text
custom_agent/
├── app/
│   ├── __init__.py
│   └── api/
│       └── providers.py
├── requirements.txt
├── run.py
└── README.md
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python run.py
```

Server starts at `http://127.0.0.1:5000`.

## Swagger Docs

After starting the server, open:

- `http://127.0.0.1:5000/apidocs`

## API Endpoints

- `POST /providers`
- `GET /providers`
- `GET /providers/<id>`
- `PUT /providers/<id>`
- `DELETE /providers/<id>`


#testinh