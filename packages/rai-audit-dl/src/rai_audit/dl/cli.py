import typer

dl_app = typer.Typer(name="dl", help="Audit deep learning models (image, medical, scientific). [Phase 5 — coming soon]")


def register(parent: typer.Typer) -> None:
    parent.add_typer(dl_app)


@dl_app.command("run")
def dl_run() -> None:
    """Run a deep learning model audit. [Not yet implemented — Phase 5]"""
    typer.echo("rai-audit-dl is not yet implemented. See the roadmap for Phase 5.")
    raise typer.Exit(1)
