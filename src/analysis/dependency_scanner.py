"""Dependency file scanner for detecting vulnerable packages."""

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class Dependency:
    """Represents a project dependency."""

    name: str
    version: str | None = None
    version_specifier: str | None = None
    ecosystem: str = "pypi"
    file_path: str = ""
    line_number: int = 0


@dataclass
class DependencyScanResult:
    """Result of scanning a codebase for dependencies."""

    dependencies: list[Dependency] = field(default_factory=list)
    files_scanned: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class DependencyScanner:
    """Scans codebases for dependencies."""

    # Patterns for different dependency files
    DEPENDENCY_FILES = {
        "requirements.txt": "pypi",
        "requirements-*.txt": "pypi",
        "*requirements.txt": "pypi",
        "Pipfile": "pypi",
        "Pipfile.lock": "pypi",
        "pyproject.toml": "pypi",
        "setup.py": "pypi",
        "setup.cfg": "pypi",
        "package.json": "npm",
        "package-lock.json": "npm",
        "yarn.lock": "npm",
        "go.mod": "go",
        "go.sum": "go",
        "Cargo.toml": "rust",
        "Cargo.lock": "rust",
        "Gemfile": "rubygems",
        "Gemfile.lock": "rubygems",
        "pom.xml": "maven",
        "build.gradle": "maven",
    }

    def __init__(self, codebase_path: str | Path) -> None:
        self.codebase_path = Path(codebase_path)

    async def scan(self) -> DependencyScanResult:
        """Scan the codebase for all dependencies."""
        result = DependencyScanResult()

        for pattern, ecosystem in self.DEPENDENCY_FILES.items():
            for file_path in self.codebase_path.rglob(pattern):
                # Skip node_modules, venv, etc.
                if self._should_skip_path(file_path):
                    continue

                try:
                    deps = self._parse_dependency_file(file_path, ecosystem)
                    result.dependencies.extend(deps)
                    result.files_scanned.append(str(file_path))
                except Exception as e:
                    error_msg = f"Error parsing {file_path}: {e}"
                    logger.warning(error_msg)
                    result.errors.append(error_msg)

        # Deduplicate dependencies
        seen = set()
        unique_deps = []
        for dep in result.dependencies:
            key = (dep.name.lower(), dep.ecosystem)
            if key not in seen:
                seen.add(key)
                unique_deps.append(dep)
        result.dependencies = unique_deps

        return result

    def _should_skip_path(self, path: Path) -> bool:
        """Check if a path should be skipped."""
        skip_dirs = {
            "node_modules",
            "venv",
            ".venv",
            "env",
            ".env",
            "__pycache__",
            ".git",
            ".tox",
            "dist",
            "build",
            "target",
            "vendor",
        }
        return any(part in skip_dirs for part in path.parts)

    def _parse_dependency_file(
        self,
        file_path: Path,
        ecosystem: str,
    ) -> list[Dependency]:
        """Parse a dependency file and extract dependencies."""
        filename = file_path.name

        if filename == "requirements.txt" or filename.endswith("requirements.txt"):
            return self._parse_requirements_txt(file_path)
        elif filename == "pyproject.toml":
            return self._parse_pyproject_toml(file_path)
        elif filename == "Pipfile":
            return self._parse_pipfile(file_path)
        elif filename == "Pipfile.lock":
            return self._parse_pipfile_lock(file_path)
        elif filename == "package.json":
            return self._parse_package_json(file_path)
        elif filename == "package-lock.json":
            return self._parse_package_lock_json(file_path)
        elif filename == "go.mod":
            return self._parse_go_mod(file_path)

        return []

    def _parse_requirements_txt(self, file_path: Path) -> list[Dependency]:
        """Parse requirements.txt format."""
        deps = []
        content = file_path.read_text(encoding="utf-8", errors="ignore")

        # Pattern for package with optional version specifier
        pattern = re.compile(
            r"^([a-zA-Z0-9][\w.-]*)"  # Package name
            r"(?:\[[\w,.-]+\])?"  # Optional extras
            r"([<>=!~].+)?$"  # Optional version specifier
        )

        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()

            # Skip comments, empty lines, -r references
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Handle environment markers
            if ";" in line:
                line = line.split(";")[0].strip()

            match = pattern.match(line)
            if match:
                name = match.group(1)
                version_spec = match.group(2) or ""

                # Extract version from specifier
                version = None
                if version_spec:
                    version_match = re.search(r"[<>=!~]+(.+)", version_spec)
                    if version_match:
                        version = version_match.group(1).strip()

                deps.append(
                    Dependency(
                        name=name,
                        version=version,
                        version_specifier=version_spec,
                        ecosystem="pypi",
                        file_path=str(file_path),
                        line_number=line_num,
                    )
                )

        return deps

    def _parse_pyproject_toml(self, file_path: Path) -> list[Dependency]:
        """Parse pyproject.toml for dependencies."""
        deps = []
        content = file_path.read_text(encoding="utf-8", errors="ignore")

        # Simple TOML parsing for dependencies section
        # Looking for [project] dependencies or [tool.poetry.dependencies]
        in_deps_section = False
        current_section = ""

        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()

            # Track section headers
            if stripped.startswith("["):
                current_section = stripped
                in_deps_section = (
                    current_section
                    in ("[project]", "[tool.poetry.dependencies]", "[project.dependencies]")
                    or current_section.startswith("[project.optional-dependencies")
                )
                continue

            if not in_deps_section:
                continue

            # Parse dependency lines
            if "=" in stripped and not stripped.startswith("#"):
                # Handle poetry style: package = "^1.0.0" or package = {version = "..."}
                if current_section == "[tool.poetry.dependencies]":
                    match = re.match(r'^([a-zA-Z0-9][\w.-]*)\s*=', stripped)
                    if match:
                        name = match.group(1)
                        if name.lower() != "python":
                            deps.append(
                                Dependency(
                                    name=name,
                                    ecosystem="pypi",
                                    file_path=str(file_path),
                                    line_number=line_num,
                                )
                            )

            # Handle list style dependencies in [project]
            elif stripped.startswith('"') and "==" in stripped:
                # Format: "package==1.0.0"
                match = re.match(r'"([a-zA-Z0-9][\w.-]*)([<>=!].+)?"', stripped)
                if match:
                    deps.append(
                        Dependency(
                            name=match.group(1),
                            version_specifier=match.group(2),
                            ecosystem="pypi",
                            file_path=str(file_path),
                            line_number=line_num,
                        )
                    )

        return deps

    def _parse_pipfile(self, file_path: Path) -> list[Dependency]:
        """Parse Pipfile for dependencies."""
        deps = []
        content = file_path.read_text(encoding="utf-8", errors="ignore")

        in_packages = False
        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()

            if stripped in ("[packages]", "[dev-packages]"):
                in_packages = True
                continue
            elif stripped.startswith("["):
                in_packages = False
                continue

            if in_packages and "=" in stripped:
                match = re.match(r'^([a-zA-Z0-9][\w.-]*)\s*=', stripped)
                if match:
                    deps.append(
                        Dependency(
                            name=match.group(1),
                            ecosystem="pypi",
                            file_path=str(file_path),
                            line_number=line_num,
                        )
                    )

        return deps

    def _parse_pipfile_lock(self, file_path: Path) -> list[Dependency]:
        """Parse Pipfile.lock for exact versions."""
        deps = []
        content = file_path.read_text(encoding="utf-8", errors="ignore")

        try:
            data = json.loads(content)
            for section in ["default", "develop"]:
                packages = data.get(section, {})
                for name, info in packages.items():
                    version = info.get("version", "").lstrip("=")
                    deps.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem="pypi",
                            file_path=str(file_path),
                        )
                    )
        except json.JSONDecodeError:
            pass

        return deps

    def _parse_package_json(self, file_path: Path) -> list[Dependency]:
        """Parse package.json for npm dependencies."""
        deps = []
        content = file_path.read_text(encoding="utf-8", errors="ignore")

        try:
            data = json.loads(content)
            for dep_type in ["dependencies", "devDependencies", "peerDependencies"]:
                packages = data.get(dep_type, {})
                for name, version in packages.items():
                    deps.append(
                        Dependency(
                            name=name,
                            version_specifier=version,
                            ecosystem="npm",
                            file_path=str(file_path),
                        )
                    )
        except json.JSONDecodeError:
            pass

        return deps

    def _parse_package_lock_json(self, file_path: Path) -> list[Dependency]:
        """Parse package-lock.json for exact npm versions."""
        deps = []
        content = file_path.read_text(encoding="utf-8", errors="ignore")

        try:
            data = json.loads(content)
            # package-lock.json v2/v3 format
            packages = data.get("packages", {})
            for path, info in packages.items():
                if path == "":  # Root package
                    continue
                name = path.split("node_modules/")[-1]
                if "/" not in name or name.startswith("@"):  # Skip nested deps except scoped
                    deps.append(
                        Dependency(
                            name=name,
                            version=info.get("version"),
                            ecosystem="npm",
                            file_path=str(file_path),
                        )
                    )
        except json.JSONDecodeError:
            pass

        return deps

    def _parse_go_mod(self, file_path: Path) -> list[Dependency]:
        """Parse go.mod for Go dependencies."""
        deps = []
        content = file_path.read_text(encoding="utf-8", errors="ignore")

        in_require = False
        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()

            if stripped.startswith("require ("):
                in_require = True
                continue
            elif stripped == ")":
                in_require = False
                continue

            # Single-line require or inside require block
            if stripped.startswith("require ") or in_require:
                # Pattern: module/path v1.2.3
                parts = stripped.replace("require ", "").split()
                if len(parts) >= 2:
                    module = parts[0]
                    version = parts[1]
                    deps.append(
                        Dependency(
                            name=module,
                            version=version.lstrip("v"),
                            ecosystem="go",
                            file_path=str(file_path),
                            line_number=line_num,
                        )
                    )

        return deps

    def find_vulnerable_dependencies(
        self,
        dependencies: list[Dependency],
        vulnerable_packages: list[str],
    ) -> list[Dependency]:
        """Find dependencies that match known vulnerable packages."""
        vulnerable = []
        vuln_set = {pkg.lower() for pkg in vulnerable_packages}

        for dep in dependencies:
            if dep.name.lower() in vuln_set:
                vulnerable.append(dep)

        return vulnerable
