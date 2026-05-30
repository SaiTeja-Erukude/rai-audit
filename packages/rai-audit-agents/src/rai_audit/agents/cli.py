import typer

agents_app = typer.Typer(name="agents", help="Audit agentic AI systems. [Phase 6 — coming soon]")


def register(parent: typer.Typer) -> None:
    parent.add_typer(agents_app)


@agents_app.command("run")
def agents_run() -> None:
    """Run an agent audit. [Not yet implemented — Phase 6]"""
    typer.echo("rai-audit-agents is not yet implemented. See the roadmap for Phase 6.")
    raise typer.Exit(1)
