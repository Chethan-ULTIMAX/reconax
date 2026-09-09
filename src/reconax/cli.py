import typer

app = typer.Typer(
    name="reconax",
    help="A simple, developer-friendly website analyzer.",
)


@app.command()
def main(url: str):
    """Analyze a website URL."""
    typer.echo(f"ReconAx → {url}")


if __name__ == "__main__":
    app()
