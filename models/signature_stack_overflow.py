import pathlib
from dataclasses import dataclass

import yaml


@dataclass(slots=True)
class Signature:
    """ Class that handles loaded signature objects. Signatures
    define what to search for in Stack Overflow and where to search for it.
    They also contain regex patterns to validate data that is found"""

    name: str
    id: str
    status: bool
    author: str
    date: str
    version: str
    description: str
    severity: int
    watchman_apps: list
    scope: list
    test_cases: dataclass
    search_strings: str
    patterns: str


@dataclass(slots=True)
class TestCases:
    match_cases: list
    fail_cases: list


def load_from_yaml(sig_path: pathlib.PosixPath) -> list[Signature]:
    """Load YAML file and return a Signature object

    Args:
        sig_path: Path of YAML file
    Returns:
        Signature object with fields populated from the YAML
        signature file
    """

    with open(sig_path) as yaml_file:
        yaml_import = yaml.safe_load(yaml_file)

        output = []
        for sig in yaml_import.get('signatures'):
            if 'stack_overflow' in sig.get('watchman_apps'):
                output.append(
                    Signature(
                        name=sig.get('name'),
                        id=sig.get('id'),
                        status=sig.get('status'),
                        author=sig.get('author'),
                        date=sig.get('date'),
                        version=sig.get('version'),
                        description=sig.get('description'),
                        severity=sig.get('severity'),
                        watchman_apps=sig.get('watchman_apps'),
                        scope=sig.get('watchman_apps').get('stack_overflow').get('scope'),
                        test_cases=TestCases(
                            match_cases=sig.get('test_cases').get('match_cases'),
                            fail_cases=sig.get('test_cases').get('fail_cases')
                        ),
                        search_strings=sig.get('watchman_apps').get('stack_overflow').get('search_strings'),
                        patterns=sig.get('patterns')
                    )
                )

    return output