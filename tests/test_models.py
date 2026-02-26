"""Tests for Pydantic request/response models."""
import pytest
from pydantic import ValidationError

from app.models import (
    AdminLoginRequest,
    CommandRequest,
    NEVER_EXPIRES_SECONDS,
    TokenCreateRequest,
    TokenUpdateEntitiesRequest,
    TokenUpdateExpiryRequest,
)


class TestTokenCreateRequest:
    def test_valid_minimal(self):
        t = TokenCreateRequest(
            label="Guest",
            entity_ids=["light.living_room"],
            expires_in_seconds=3600,
        )
        assert t.label == "Guest"
        assert t.slug is None

    def test_valid_all_fields(self):
        t = TokenCreateRequest(
            label="Full",
            slug="my-slug",
            entity_ids=["light.a", "switch.b"],
            expires_in_seconds=7200,
            ip_allowlist=["192.168.1.0/24"],
        )
        assert t.slug == "my-slug"
        assert t.ip_allowlist == ["192.168.1.0/24"]

    def test_empty_label_rejected(self):
        with pytest.raises(ValidationError):
            TokenCreateRequest(
                label="",
                entity_ids=["light.a"],
                expires_in_seconds=3600,
            )

    def test_label_too_long(self):
        with pytest.raises(ValidationError):
            TokenCreateRequest(
                label="x" * 201,
                entity_ids=["light.a"],
                expires_in_seconds=3600,
            )

    def test_empty_entity_ids_rejected(self):
        with pytest.raises(ValidationError):
            TokenCreateRequest(
                label="Guest",
                entity_ids=[],
                expires_in_seconds=3600,
            )

    def test_invalid_slug_pattern(self):
        with pytest.raises(ValidationError):
            TokenCreateRequest(
                label="Guest",
                slug="UPPER_CASE",
                entity_ids=["light.a"],
                expires_in_seconds=3600,
            )

    def test_slug_with_spaces(self):
        with pytest.raises(ValidationError):
            TokenCreateRequest(
                label="Guest",
                slug="has spaces",
                entity_ids=["light.a"],
                expires_in_seconds=3600,
            )

    def test_zero_expires_rejected(self):
        with pytest.raises(ValidationError):
            TokenCreateRequest(
                label="Guest",
                entity_ids=["light.a"],
                expires_in_seconds=0,
            )

    def test_negative_expires_rejected(self):
        with pytest.raises(ValidationError):
            TokenCreateRequest(
                label="Guest",
                entity_ids=["light.a"],
                expires_in_seconds=-1,
            )

    def test_never_expires_value_accepted(self):
        """NEVER_EXPIRES_SECONDS is a valid expires_in_seconds value (gt=0)."""
        t = TokenCreateRequest(
            label="Forever",
            entity_ids=["light.a"],
            expires_in_seconds=NEVER_EXPIRES_SECONDS,
        )
        assert t.expires_in_seconds == NEVER_EXPIRES_SECONDS

    def test_valid_slug_patterns(self):
        """Slugs with lowercase, digits, hyphens, underscores are valid."""
        for slug in ["abc", "test-123", "my_token", "a-b_c"]:
            t = TokenCreateRequest(
                label="Guest",
                slug=slug,
                entity_ids=["light.a"],
                expires_in_seconds=3600,
            )
            assert t.slug == slug


class TestTokenUpdateEntitiesRequest:
    def test_valid(self):
        r = TokenUpdateEntitiesRequest(entity_ids=["light.a", "switch.b"])
        assert len(r.entity_ids) == 2

    def test_empty_rejected(self):
        with pytest.raises(ValidationError):
            TokenUpdateEntitiesRequest(entity_ids=[])


class TestTokenUpdateExpiryRequest:
    def test_valid(self):
        r = TokenUpdateExpiryRequest(expires_in_seconds=3600)
        assert r.expires_in_seconds == 3600

    def test_zero_rejected(self):
        with pytest.raises(ValidationError):
            TokenUpdateExpiryRequest(expires_in_seconds=0)


class TestCommandRequest:
    def test_valid_with_data(self):
        r = CommandRequest(
            entity_id="light.living_room",
            service="light.turn_on",
            data={"brightness": 255},
        )
        assert r.data["brightness"] == 255

    def test_valid_without_data(self):
        r = CommandRequest(entity_id="light.living_room", service="turn_off")
        assert r.data == {}

    def test_missing_entity_id(self):
        with pytest.raises(ValidationError):
            CommandRequest(service="turn_on")

    def test_missing_service(self):
        with pytest.raises(ValidationError):
            CommandRequest(entity_id="light.living_room")


class TestAdminLoginRequest:
    def test_valid(self):
        r = AdminLoginRequest(username="admin", password="secret")
        assert r.username == "admin"


def test_never_expires_is_2099():
    """NEVER_EXPIRES_SECONDS matches 2099-12-31T00:00:00Z."""
    assert NEVER_EXPIRES_SECONDS == 4102444800
