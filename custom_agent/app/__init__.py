from flask import Flask
from flasgger import Swagger

from app.api.providers import providers_bp


def create_app() -> Flask:
    app = Flask(__name__)
    swagger_template = {
        "swagger": "2.0",
        "info": {
            "title": "LLM Providers API",
            "description": "Simple CRUD API for managing LLM providers.",
            "version": "1.0.0",
        },
        "basePath": "/",
        "schemes": ["http", "https"],
    }
    Swagger(app, template=swagger_template)
    app.register_blueprint(providers_bp, url_prefix="/providers")
    return app
