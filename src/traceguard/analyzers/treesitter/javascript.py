"""Tree-sitter based JavaScript/TypeScript analyzer for dependency usage detection."""

import json
import logging
from pathlib import Path
from typing import Optional

import tree_sitter_javascript as tsjs
from tree_sitter import Language, Parser

from traceguard.analyzers.base import DependencyAnalyzer
from traceguard.schemas.analysis import UsageEvidenceSchema

logger = logging.getLogger(__name__)

# File extensions to analyze
JS_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}


class JavaScriptAnalyzer(DependencyAnalyzer):
    """Analyzer for JavaScript/TypeScript codebases using Tree-sitter.

    Detects package usage through:
    - ES6 import statements
    - CommonJS require() calls
    - Dynamic imports
    """

    def __init__(self):
        """Initialize the JavaScript analyzer with Tree-sitter parser."""
        self._js_language = Language(tsjs.language())
        self._parser = Parser(self._js_language)

    @property
    def supported_ecosystems(self) -> list[str]:
        return ["npm", "yarn", "pnpm", "node"]

    async def find_package_usage(
        self,
        codebase_path: Path,
        package_name: str,
        ecosystem: str,
    ) -> list[UsageEvidenceSchema]:
        """Find all usages of a package in JavaScript/TypeScript files."""
        evidence: list[UsageEvidenceSchema] = []
        codebase_path = Path(codebase_path)

        if not codebase_path.exists():
            logger.error(f"Codebase path does not exist: {codebase_path}")
            return evidence

        # Find all JS/TS files, excluding node_modules
        js_files = self._find_js_files(codebase_path)
        logger.info(f"Found {len(js_files)} JavaScript/TypeScript files to analyze")

        for file_path in js_files:
            try:
                file_evidence = await self._analyze_file(file_path, package_name)
                evidence.extend(file_evidence)
            except Exception as e:
                logger.warning(f"Error analyzing {file_path}: {e}")
                continue

        logger.info(f"Found {len(evidence)} usages of {package_name}")
        return evidence

    async def get_installed_version(
        self,
        codebase_path: Path,
        package_name: str,
        ecosystem: str,
    ) -> Optional[str]:
        """Get the installed version of a package from lockfiles."""
        codebase_path = Path(codebase_path)

        # Try package-lock.json first
        package_lock = codebase_path / "package-lock.json"
        if package_lock.exists():
            version = self._get_version_from_package_lock(package_lock, package_name)
            if version:
                return version

        # Try yarn.lock
        yarn_lock = codebase_path / "yarn.lock"
        if yarn_lock.exists():
            version = self._get_version_from_yarn_lock(yarn_lock, package_name)
            if version:
                return version

        # Try pnpm-lock.yaml
        pnpm_lock = codebase_path / "pnpm-lock.yaml"
        if pnpm_lock.exists():
            version = self._get_version_from_pnpm_lock(pnpm_lock, package_name)
            if version:
                return version

        # Fall back to package.json dependencies
        package_json = codebase_path / "package.json"
        if package_json.exists():
            version = self._get_version_from_package_json(package_json, package_name)
            if version:
                return version

        return None

    def _find_js_files(self, codebase_path: Path) -> list[Path]:
        """Find all JavaScript/TypeScript files, excluding node_modules."""
        js_files = []

        for ext in JS_EXTENSIONS:
            for file_path in codebase_path.rglob(f"*{ext}"):
                # Skip node_modules and other common excluded directories
                path_parts = file_path.parts
                if any(
                    part in ("node_modules", ".git", "dist", "build", "coverage")
                    for part in path_parts
                ):
                    continue
                js_files.append(file_path)

        return js_files

    async def _analyze_file(
        self, file_path: Path, package_name: str
    ) -> list[UsageEvidenceSchema]:
        """Analyze a single file for package usage."""
        evidence: list[UsageEvidenceSchema] = []

        try:
            content = file_path.read_bytes()
            tree = self._parser.parse(content)

            # Find import statements
            import_evidence = self._find_imports(tree, content, file_path, package_name)
            evidence.extend(import_evidence)

            # Find require() calls
            require_evidence = self._find_requires(tree, content, file_path, package_name)
            evidence.extend(require_evidence)

            # Find dynamic imports
            dynamic_import_evidence = self._find_dynamic_imports(
                tree, content, file_path, package_name
            )
            evidence.extend(dynamic_import_evidence)

        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")

        return evidence

    def _find_imports(
        self,
        tree,
        content: bytes,
        file_path: Path,
        package_name: str,
    ) -> list[UsageEvidenceSchema]:
        """Find ES6 import statements for the package."""
        evidence = []

        # Query for import statements
        # import x from 'package'
        # import { x } from 'package'
        # import * as x from 'package'
        query_text = """
        (import_statement
          source: (string) @import_source)
        """

        query = self._js_language.query(query_text)
        captures = query.captures(tree.root_node)

        for node, name in captures:
            source_text = content[node.start_byte : node.end_byte].decode("utf-8")
            # Remove quotes
            source_text = source_text.strip("'\"")

            if self._matches_package(source_text, package_name):
                # Get the full import statement line
                line_start = content.rfind(b"\n", 0, node.start_byte) + 1
                line_end = content.find(b"\n", node.end_byte)
                if line_end == -1:
                    line_end = len(content)
                code_snippet = content[line_start:line_end].decode("utf-8").strip()

                evidence.append(
                    UsageEvidenceSchema(
                        file_path=str(file_path),
                        line_number=node.start_point[0] + 1,  # 1-indexed
                        usage_type="import",
                        code_snippet=code_snippet,
                        package_name=package_name,
                    )
                )

        return evidence

    def _find_requires(
        self,
        tree,
        content: bytes,
        file_path: Path,
        package_name: str,
    ) -> list[UsageEvidenceSchema]:
        """Find CommonJS require() calls for the package."""
        evidence = []

        # Query for require() calls
        query_text = """
        (call_expression
          function: (identifier) @func_name
          arguments: (arguments
            (string) @require_source))
        """

        query = self._js_language.query(query_text)
        captures = query.captures(tree.root_node)

        # Process captures in pairs (func_name, require_source)
        i = 0
        while i < len(captures):
            node, name = captures[i]

            if name == "func_name":
                func_text = content[node.start_byte : node.end_byte].decode("utf-8")
                if func_text == "require" and i + 1 < len(captures):
                    source_node, source_name = captures[i + 1]
                    if source_name == "require_source":
                        source_text = content[
                            source_node.start_byte : source_node.end_byte
                        ].decode("utf-8")
                        source_text = source_text.strip("'\"")

                        if self._matches_package(source_text, package_name):
                            # Get the full line
                            line_start = content.rfind(b"\n", 0, node.start_byte) + 1
                            line_end = content.find(b"\n", source_node.end_byte)
                            if line_end == -1:
                                line_end = len(content)
                            code_snippet = content[line_start:line_end].decode("utf-8").strip()

                            evidence.append(
                                UsageEvidenceSchema(
                                    file_path=str(file_path),
                                    line_number=node.start_point[0] + 1,
                                    usage_type="require",
                                    code_snippet=code_snippet,
                                    package_name=package_name,
                                )
                            )
                    i += 1
            i += 1

        return evidence

    def _find_dynamic_imports(
        self,
        tree,
        content: bytes,
        file_path: Path,
        package_name: str,
    ) -> list[UsageEvidenceSchema]:
        """Find dynamic import() calls for the package."""
        evidence = []

        # Query for dynamic import() expressions
        # import('package')
        query_text = """
        (call_expression
          function: (import)
          arguments: (arguments
            (string) @import_source))
        """

        query = self._js_language.query(query_text)
        captures = query.captures(tree.root_node)

        for node, name in captures:
            source_text = content[node.start_byte : node.end_byte].decode("utf-8")
            source_text = source_text.strip("'\"")

            if self._matches_package(source_text, package_name):
                line_start = content.rfind(b"\n", 0, node.start_byte) + 1
                line_end = content.find(b"\n", node.end_byte)
                if line_end == -1:
                    line_end = len(content)
                code_snippet = content[line_start:line_end].decode("utf-8").strip()

                evidence.append(
                    UsageEvidenceSchema(
                        file_path=str(file_path),
                        line_number=node.start_point[0] + 1,
                        usage_type="dynamic_import",
                        code_snippet=code_snippet,
                        package_name=package_name,
                    )
                )

        return evidence

    def _matches_package(self, import_source: str, package_name: str) -> bool:
        """Check if an import source matches the package name.

        Handles:
        - Exact matches: 'lodash' matches 'lodash'
        - Subpath imports: 'lodash/debounce' matches 'lodash'
        - Scoped packages: '@types/node' matches '@types/node'
        """
        # Normalize to lowercase for comparison
        import_source = import_source.lower()
        package_name = package_name.lower()

        # Exact match
        if import_source == package_name:
            return True

        # Subpath import (e.g., 'lodash/debounce' for 'lodash')
        if import_source.startswith(f"{package_name}/"):
            return True

        return False

    def _get_version_from_package_lock(
        self, lock_path: Path, package_name: str
    ) -> Optional[str]:
        """Get package version from package-lock.json."""
        try:
            with open(lock_path) as f:
                lock_data = json.load(f)

            # Check packages (npm v7+)
            packages = lock_data.get("packages", {})
            pkg_key = f"node_modules/{package_name}"
            if pkg_key in packages:
                return packages[pkg_key].get("version")

            # Check dependencies (npm v6)
            dependencies = lock_data.get("dependencies", {})
            if package_name in dependencies:
                return dependencies[package_name].get("version")

        except Exception as e:
            logger.warning(f"Error reading package-lock.json: {e}")

        return None

    def _get_version_from_yarn_lock(
        self, lock_path: Path, package_name: str
    ) -> Optional[str]:
        """Get package version from yarn.lock (simplified parsing)."""
        try:
            content = lock_path.read_text()
            lines = content.split("\n")

            # Simple yarn.lock parser
            in_package = False
            for line in lines:
                # Check for package header (e.g., 'lodash@^4.17.0:')
                if line and not line.startswith(" "):
                    # Check if this is our package
                    if line.startswith(f'"{package_name}@') or line.startswith(
                        f"{package_name}@"
                    ):
                        in_package = True
                    else:
                        in_package = False
                elif in_package and line.strip().startswith("version"):
                    # Extract version
                    version = line.split('"')[1] if '"' in line else line.split()[-1]
                    return version

        except Exception as e:
            logger.warning(f"Error reading yarn.lock: {e}")

        return None

    def _get_version_from_pnpm_lock(
        self, lock_path: Path, package_name: str
    ) -> Optional[str]:
        """Get package version from pnpm-lock.yaml (simplified parsing)."""
        try:
            # Simple YAML parsing without external dependency
            content = lock_path.read_text()
            lines = content.split("\n")

            # Look for the package in dependencies
            for i, line in enumerate(lines):
                if f"/{package_name}/" in line or f"'{package_name}':" in line:
                    # Try to find version in the same or next line
                    if "@" in line:
                        # Format: /package@version
                        parts = line.split("@")
                        if len(parts) >= 2:
                            version = parts[-1].rstrip(":")
                            return version

        except Exception as e:
            logger.warning(f"Error reading pnpm-lock.yaml: {e}")

        return None

    def _get_version_from_package_json(
        self, package_json_path: Path, package_name: str
    ) -> Optional[str]:
        """Get package version range from package.json."""
        try:
            with open(package_json_path) as f:
                pkg_data = json.load(f)

            # Check all dependency types
            for dep_type in [
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            ]:
                deps = pkg_data.get(dep_type, {})
                if package_name in deps:
                    return deps[package_name]

        except Exception as e:
            logger.warning(f"Error reading package.json: {e}")

        return None
