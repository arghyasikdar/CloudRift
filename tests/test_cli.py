from typer.testing import CliRunner

from cloudrift.cli.main import app


def test_cli_help() -> None:
    result = CliRunner().invoke(app, ["scan", "--help"])

    assert result.exit_code == 0
    assert "cloud storage exposure intelligence" in result.output.lower()
