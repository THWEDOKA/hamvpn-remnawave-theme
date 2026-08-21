from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_panel_base_image_is_immutable():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert dockerfile.startswith(
        "FROM remnawave/backend@sha256:361f9bb0b183d4fcefea2f1f7163db490e2aa1ec3b4bdde016a9ab9229ce956b"
    )
    assert "remnawave/backend:latest" not in dockerfile


def test_theme_injects_infrastructure_navigation():
    installer = (ROOT / "scripts" / "install-theme.sh").read_text(encoding="utf-8")
    assert "/hamvpn/hamvpn-infrastructure-nav.js" in installer

