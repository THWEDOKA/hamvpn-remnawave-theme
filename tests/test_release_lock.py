from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_panel_base_image_is_immutable():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert (
        "FROM remnawave/backend@sha256:"
        "361f9bb0b183d4fcefea2f1f7163db490e2aa1ec3b4bdde016a9ab9229ce956b"
        in dockerfile
    )
    assert "remnawave/backend:latest" not in dockerfile


def test_frontend_is_pinned_and_infrastructure_is_native():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    patch = (ROOT / "frontend" / "remnawave-2.8.1.patch").read_text(encoding="utf-8")
    assert "9d671520067f73b2beb96c282f2ce2ff7b7a9a00" in dockerfile
    assert "VERSION=2.8.1" not in dockerfile
    assert "/dashboard/management/infrastructure" in patch
    assert "InfrastructurePage" in patch
