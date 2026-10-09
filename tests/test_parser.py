"""
test_parser.py — Tests for manifest_parser (lockfile → NetworkX graph)
Hyron AI · FUSION 2026 · CSB-03
"""

import json
import tempfile
from pathlib import Path

import networkx as nx
import pytest

from backend.services.manifest_parser import load_project, load_projects


# ---------- fixtures ----------

MINIMAL_LOCK = {
    "lockfileVersion": 2,
    "name": "test-app",
    "version": "1.0.0",
    "packages": {
        "": {
            "dependencies": {"express": "^4.17.1"},
            "devDependencies": {"mocha": "^7.0.0"},
        },
        "node_modules/express": {
            "version": "4.17.1",
            "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz",
            "dependencies": {"qs": "^6.7.0"},
        },
        "node_modules/qs": {
            "version": "6.7.0",
            "resolved": "https://registry.npmjs.org/qs/-/qs-6.7.0.tgz",
        },
        "node_modules/mocha": {
            "version": "7.0.0",
            "dev": True,
            "resolved": "https://registry.npmjs.org/mocha/-/mocha-7.0.0.tgz",
        },
    },
}


@pytest.fixture
def lock_dir(tmp_path):
    """Create a temp directory with a package-lock.json."""
    proj_dir = tmp_path / "test-app"
    proj_dir.mkdir()
    (proj_dir / "package-lock.json").write_text(json.dumps(MINIMAL_LOCK))
    return proj_dir


# ---------- tests ----------

class TestLoadProject:
    def test_returns_digraph(self, lock_dir):
        G = load_project(lock_dir / "package-lock.json")
        assert isinstance(G, nx.DiGraph)

    def test_project_node_exists(self, lock_dir):
        G = load_project(lock_dir / "package-lock.json")
        project_nodes = [n for n, d in G.nodes(data=True) if d.get("kind") == "project"]
        assert len(project_nodes) == 1
        assert project_nodes[0] == "proj:test-app"

    def test_package_nodes(self, lock_dir):
        G = load_project(lock_dir / "package-lock.json")
        pkg_nodes = [n for n, d in G.nodes(data=True) if d.get("kind") == "pkg"]
        pkg_names = {d["name"] for _, d in G.nodes(data=True) if d.get("kind") == "pkg"}
        assert "express" in pkg_names
        assert "qs" in pkg_names
        assert "mocha" in pkg_names

    def test_direct_dependency_edge(self, lock_dir):
        G = load_project(lock_dir / "package-lock.json")
        proj_node = "proj:test-app"
        pkg_nodes  = {d["name"]: n for n, d in G.nodes(data=True) if d.get("kind") == "pkg"}
        assert G.has_edge(proj_node, pkg_nodes["express"])

    def test_transitive_dependency_edge(self, lock_dir):
        G = load_project(lock_dir / "package-lock.json")
        pkg_nodes = {d["name"]: n for n, d in G.nodes(data=True) if d.get("kind") == "pkg"}
        assert G.has_edge(pkg_nodes["express"], pkg_nodes["qs"])

    def test_dev_flag(self, lock_dir):
        G = load_project(lock_dir / "package-lock.json")
        mocha_node = next(
            n for n, d in G.nodes(data=True)
            if d.get("kind") == "pkg" and d.get("name") == "mocha"
        )
        assert G.nodes[mocha_node]["dev"] is True

    def test_lockfile_v1_raises(self, tmp_path):
        proj = tmp_path / "old-app"
        proj.mkdir()
        (proj / "package-lock.json").write_text(json.dumps({"lockfileVersion": 1}))
        with pytest.raises(ValueError, match="lockfileVersion 1 unsupported"):
            load_project(proj / "package-lock.json")

    def test_path_reachable_from_project(self, lock_dir):
        G = load_project(lock_dir / "package-lock.json")
        proj_node = "proj:test-app"
        pkg_nodes = {d["name"]: n for n, d in G.nodes(data=True) if d.get("kind") == "pkg"}
        # qs is reachable from project via express
        assert nx.has_path(G, proj_node, pkg_nodes["qs"])


class TestLoadProjects:
    def test_compose_multiple(self, tmp_path):
        # Create two minimal projects
        for i, name in enumerate(["app-a", "app-b"]):
            d = tmp_path / name
            d.mkdir()
            lock = {**MINIMAL_LOCK, "name": name}
            (d / "package-lock.json").write_text(json.dumps(lock))

        G = load_projects([
            tmp_path / "app-a" / "package-lock.json",
            tmp_path / "app-b" / "package-lock.json",
        ])
        proj_nodes = [n for n, d in G.nodes(data=True) if d.get("kind") == "project"]
        assert len(proj_nodes) == 2
