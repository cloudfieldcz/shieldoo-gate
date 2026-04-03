"""Ecosystem-specific file extractors for AI scanner analysis."""

from extractors.pypi import extract as extract_pypi
from extractors.npm import extract as extract_npm
from extractors.nuget import extract as extract_nuget
from extractors.maven import extract as extract_maven
from extractors.rubygems import extract as extract_rubygems

EXTRACTORS: dict[str, callable] = {
    "pypi": extract_pypi,
    "npm": extract_npm,
    "nuget": extract_nuget,
    "maven": extract_maven,
    "rubygems": extract_rubygems,
}
