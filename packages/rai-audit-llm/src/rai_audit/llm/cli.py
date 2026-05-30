import typer

llm_app = typer.Typer(name="llm", help="Audit LLM applications and RAG systems. [Phase 4 — coming soon]")


def register(parent: typer.Typer) -> None:
    parent.add_typer(llm_app)


@llm_app.command("run")
def llm_run() -> None:
    """Run an LLM or RAG audit. [Not yet implemented — Phase 4]"""
    typer.echo("rai-audit-llm is not yet implemented. See the roadmap for Phase 4.")
    raise typer.Exit(1)
