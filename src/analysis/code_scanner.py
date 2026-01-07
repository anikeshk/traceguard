"""Code scanner for detecting vulnerable code patterns and imports."""

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class CodeMatch:
    """Represents a code pattern match."""

    file_path: str
    line_number: int
    line_content: str
    match_type: str  # "import", "usage", "pattern"
    package_name: str | None = None
    function_name: str | None = None
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)


@dataclass
class CodeScanResult:
    """Result of scanning code for vulnerable patterns."""

    matches: list[CodeMatch] = field(default_factory=list)
    files_scanned: int = 0
    errors: list[str] = field(default_factory=list)


class CodeScanner:
    """Scans source code for vulnerable patterns and imports."""

    # File extensions to scan by ecosystem
    EXTENSIONS = {
        "pypi": [".py"],
        "npm": [".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"],
        "go": [".go"],
        "rust": [".rs"],
        "rubygems": [".rb"],
        "maven": [".java", ".kt", ".scala"],
    }

    # Directories to skip
    SKIP_DIRS = {
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
        ".mypy_cache",
        ".pytest_cache",
        "htmlcov",
        "site-packages",
    }

    def __init__(self, codebase_path: str | Path) -> None:
        self.codebase_path = Path(codebase_path)

    async def scan_for_packages(
        self,
        packages: list[str],
        ecosystem: str = "pypi",
    ) -> CodeScanResult:
        """Scan code for imports/usage of specific packages."""
        result = CodeScanResult()
        extensions = self.EXTENSIONS.get(ecosystem, [])

        for ext in extensions:
            for file_path in self.codebase_path.rglob(f"*{ext}"):
                if self._should_skip(file_path):
                    continue

                try:
                    if ecosystem == "pypi":
                        matches = self._scan_python_file(file_path, packages)
                    elif ecosystem == "npm":
                        matches = self._scan_js_file(file_path, packages)
                    else:
                        matches = self._scan_generic(file_path, packages)

                    result.matches.extend(matches)
                    result.files_scanned += 1
                except Exception as e:
                    error = f"Error scanning {file_path}: {e}"
                    logger.warning(error)
                    result.errors.append(error)

        return result

    async def scan_for_patterns(
        self,
        patterns: list[str],
        file_extensions: list[str] | None = None,
    ) -> CodeScanResult:
        """Scan code for regex patterns (e.g., vulnerable function calls)."""
        result = CodeScanResult()
        extensions = file_extensions or [".py", ".js", ".ts", ".go", ".java"]

        compiled_patterns = []
        for pattern in patterns:
            try:
                compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                result.errors.append(f"Invalid regex pattern '{pattern}': {e}")

        for ext in extensions:
            for file_path in self.codebase_path.rglob(f"*{ext}"):
                if self._should_skip(file_path):
                    continue

                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    lines = content.splitlines()

                    for line_num, line in enumerate(lines, 1):
                        for pattern in compiled_patterns:
                            if pattern.search(line):
                                match = CodeMatch(
                                    file_path=str(file_path),
                                    line_number=line_num,
                                    line_content=line.strip(),
                                    match_type="pattern",
                                    context_before=lines[max(0, line_num - 3) : line_num - 1],
                                    context_after=lines[line_num : line_num + 2],
                                )
                                result.matches.append(match)

                    result.files_scanned += 1
                except Exception as e:
                    result.errors.append(f"Error scanning {file_path}: {e}")

        return result

    def _should_skip(self, path: Path) -> bool:
        """Check if path should be skipped."""
        return any(part in self.SKIP_DIRS for part in path.parts)

    def _scan_python_file(
        self,
        file_path: Path,
        packages: list[str],
    ) -> list[CodeMatch]:
        """Scan Python file for imports and usage of packages."""
        matches = []
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        # Normalize package names for comparison
        pkg_set = {pkg.lower().replace("-", "_") for pkg in packages}
        pkg_set.update(pkg.lower() for pkg in packages)

        try:
            tree = ast.parse(content)
        except SyntaxError:
            # Fall back to regex for syntax errors
            return self._scan_python_regex(file_path, packages)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module_name = alias.name.split(".")[0]
                    if module_name.lower().replace("-", "_") in pkg_set:
                        matches.append(
                            CodeMatch(
                                file_path=str(file_path),
                                line_number=node.lineno,
                                line_content=lines[node.lineno - 1].strip(),
                                match_type="import",
                                package_name=module_name,
                            )
                        )

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    module_name = node.module.split(".")[0]
                    if module_name.lower().replace("-", "_") in pkg_set:
                        matches.append(
                            CodeMatch(
                                file_path=str(file_path),
                                line_number=node.lineno,
                                line_content=lines[node.lineno - 1].strip(),
                                match_type="import",
                                package_name=module_name,
                            )
                        )

        return matches

    def _scan_python_regex(
        self,
        file_path: Path,
        packages: list[str],
    ) -> list[CodeMatch]:
        """Fallback regex-based Python import scanning."""
        matches = []
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        import_pattern = re.compile(
            r"^\s*(?:from\s+(\w+)|import\s+(\w+))",
            re.MULTILINE,
        )

        pkg_set = {pkg.lower().replace("-", "_") for pkg in packages}
        pkg_set.update(pkg.lower() for pkg in packages)

        for line_num, line in enumerate(lines, 1):
            match = import_pattern.match(line)
            if match:
                module = match.group(1) or match.group(2)
                if module and module.lower().replace("-", "_") in pkg_set:
                    matches.append(
                        CodeMatch(
                            file_path=str(file_path),
                            line_number=line_num,
                            line_content=line.strip(),
                            match_type="import",
                            package_name=module,
                        )
                    )

        return matches

    def _scan_js_file(
        self,
        file_path: Path,
        packages: list[str],
    ) -> list[CodeMatch]:
        """Scan JavaScript/TypeScript file for imports and requires."""
        matches = []
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        pkg_set = {pkg.lower() for pkg in packages}

        # Match import statements and require calls
        patterns = [
            re.compile(r"import\s+.*?from\s+['\"](@?[\w/-]+)['\"]"),
            re.compile(r"require\s*\(\s*['\"](@?[\w/-]+)['\"]"),
            re.compile(r"import\s*\(\s*['\"](@?[\w/-]+)['\"]"),
        ]

        for line_num, line in enumerate(lines, 1):
            for pattern in patterns:
                match = pattern.search(line)
                if match:
                    module = match.group(1)
                    # Get base package name (handle scoped packages)
                    if module.startswith("@"):
                        parts = module.split("/")
                        base_pkg = "/".join(parts[:2]) if len(parts) > 1 else module
                    else:
                        base_pkg = module.split("/")[0]

                    if base_pkg.lower() in pkg_set:
                        matches.append(
                            CodeMatch(
                                file_path=str(file_path),
                                line_number=line_num,
                                line_content=line.strip(),
                                match_type="import",
                                package_name=base_pkg,
                            )
                        )

        return matches

    def _scan_generic(
        self,
        file_path: Path,
        packages: list[str],
    ) -> list[CodeMatch]:
        """Generic text search for package names."""
        matches = []
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        for pkg in packages:
            pattern = re.compile(rf'\b{re.escape(pkg)}\b', re.IGNORECASE)
            for line_num, line in enumerate(lines, 1):
                if pattern.search(line):
                    matches.append(
                        CodeMatch(
                            file_path=str(file_path),
                            line_number=line_num,
                            line_content=line.strip(),
                            match_type="usage",
                            package_name=pkg,
                        )
                    )

        return matches

    def get_file_snippet(
        self,
        file_path: str | Path,
        line_number: int,
        context_lines: int = 5,
    ) -> str:
        """Get a code snippet around a specific line."""
        path = Path(file_path)
        if not path.exists():
            return ""

        content = path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)

        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_number - 1 else "    "
            snippet_lines.append(f"{prefix}{i + 1:4d} | {lines[i]}")

        return "\n".join(snippet_lines)
