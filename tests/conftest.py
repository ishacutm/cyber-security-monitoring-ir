import pytest
from app import create_app


@pytest.fixture
def app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "test.db"),
            "SEED_DATA": False,
            "SECRET_KEY": "test-only-not-a-production-secret",
        }
    )


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def post(client):
    client.get("/")
    with client.session_transaction() as session:
        token = session["csrf_token"]

    def submit(path, data=None, **kwargs):
        return client.post(path, data={"csrf_token": token, **(data or {})}, **kwargs)

    return submit
