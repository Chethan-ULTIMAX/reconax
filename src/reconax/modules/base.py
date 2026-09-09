"""
Base interface for ReconAx analysis modules.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, TypeVar

from ..context import AnalysisContext


ResultType = TypeVar("ResultType")


class Module(ABC, Generic[ResultType]):
    """
    Base class for all ReconAx analysis modules.

    Modules receive a shared AnalysisContext and return a structured
    result object. They do not print directly to the terminal.
    """

    name: str = "module"

    def __init__(self, context: AnalysisContext) -> None:
        self.context = context

    @abstractmethod
    def analyze(self) -> ResultType:
        """
        Perform the module's analysis and return its result.
        """
        raise NotImplementedError

    def __call__(self) -> ResultType:
        """
        Allow a module instance to be called directly.
        """
        return self.analyze()