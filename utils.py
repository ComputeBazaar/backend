import uuid

def generate_api_key() -> str:
    """Generate a new UUID v4 API key as string"""
    return str(uuid.uuid4())  # always 36 chars