class ReconAx:
    """Main public API for ReconAx."""

    def __init__(self, url: str):
        self.url = url

    def analyze(self):
        """Run the ReconAx analysis.

        The HTTP client and parsers will be added incrementally during MVP development.
        """
        raise NotImplementedError("ReconAx analysis is not implemented yet")
