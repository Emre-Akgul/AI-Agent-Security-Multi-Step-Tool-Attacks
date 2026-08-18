"""Authoritative Kaggle GPU validation for JED attacks."""

from .kaggle_runner import KaggleRunnerError, KaggleRunResult, run_remote_validation

__all__ = ["KaggleRunResult", "KaggleRunnerError", "run_remote_validation"]

__version__ = "0.1.0"
