from flask import Blueprint, jsonify, request

providers_bp = Blueprint("providers", __name__)

# In-memory storage
llm_providers: dict[int, dict] = {}
current_id = 1


@providers_bp.route("", methods=["POST"])
def create_provider():
    """
    Create a provider
    ---
    tags:
      - Providers
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            name:
              type: string
            deployment:
              type: string
            version:
              type: string
            speciality:
              type: string
          required:
            - name
    responses:
      201:
        description: Provider created
      400:
        description: Name is required
    """
    global current_id

    data = request.get_json(silent=True) or {}

    if not data.get("name"):
        return jsonify({"error": "Name is required"}), 400

    provider = {
        "id": current_id,
        "name": data.get("name"),
        "deployment": data.get("deployment"),
        "version": data.get("version"),
        "speciality": data.get("speciality"),
    }

    llm_providers[current_id] = provider
    current_id += 1

    return jsonify(provider), 201


@providers_bp.route("", methods=["GET"])
def get_providers():
    """
    List all providers
    ---
    tags:
      - Providers
    responses:
      200:
        description: List of providers
    """
    return jsonify(list(llm_providers.values())), 200


@providers_bp.route("/<int:provider_id>", methods=["GET"])
def get_provider(provider_id: int):
    """
    Get one provider
    ---
    tags:
      - Providers
    parameters:
      - in: path
        name: provider_id
        type: integer
        required: true
    responses:
      200:
        description: Provider details
      404:
        description: Not found
    """
    provider = llm_providers.get(provider_id)

    if not provider:
        return jsonify({"error": "Not found"}), 404

    return jsonify(provider), 200


@providers_bp.route("/<int:provider_id>", methods=["PUT"])
def update_provider(provider_id: int):
    """
    Update a provider
    ---
    tags:
      - Providers
    consumes:
      - application/json
    parameters:
      - in: path
        name: provider_id
        type: integer
        required: true
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            name:
              type: string
            deployment:
              type: string
            version:
              type: string
            speciality:
              type: string
    responses:
      200:
        description: Provider updated
      404:
        description: Not found
    """
    provider = llm_providers.get(provider_id)

    if not provider:
        return jsonify({"error": "Not found"}), 404

    data = request.get_json(silent=True) or {}

    provider["name"] = data.get("name", provider["name"])
    provider["deployment"] = data.get("deployment", provider["deployment"])
    provider["version"] = data.get("version", provider["version"])
    provider["speciality"] = data.get("speciality", provider["speciality"])

    return jsonify(provider), 200


@providers_bp.route("/<int:provider_id>", methods=["DELETE"])
def delete_provider(provider_id: int):
    """
    Delete a provider
    ---
    tags:
      - Providers
    parameters:
      - in: path
        name: provider_id
        type: integer
        required: true
    responses:
      200:
        description: Provider deleted
      404:
        description: Not found
    """
    if provider_id not in llm_providers:
        return jsonify({"error": "Not found"}), 404

    del llm_providers[provider_id]
    return jsonify({"message": "Deleted successfully"}), 200
