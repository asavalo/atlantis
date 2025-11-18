#!/usr/bin/env python3

"""
This is a standalone script that installs the Maven build cache extension and configures it to cache all builds.
"""

import os
import subprocess
import sys
import xml.dom.minidom as MD
from pathlib import Path


def find_real_mvn():
    for path in os.environ["PATH"].split(os.pathsep):
        mvn = os.path.join(path, "mvn")
        if os.path.exists(mvn):
            if "mvn-wrapper" in os.path.realpath(mvn):
                continue
            return mvn
    raise RuntimeError("mvn not found")


ROOT_NAMESPACE = "http://maven.apache.org/EXTENSIONS/1.1.0"

EXTENSIONS_TEMPLATE = f"""
<?xml version="1.0" encoding="UTF-8"?>
<extensions xmlns="{ROOT_NAMESPACE}"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="{ROOT_NAMESPACE} https://maven.apache.org/xsd/core-extensions-1.0.0.xsd">
</extensions>
""".strip().encode()

CACHE_EXTENSION = """
<extension>
  <groupId>org.apache.maven.extensions</groupId>
  <artifactId>maven-build-cache-extension</artifactId>
  <version>1.2.0</version>
</extension>
""".strip()


def write_extension_config(extensions_path: Path):
    if extensions_path.exists():
        xml_to_edit = extensions_path.read_bytes()
    else:
        xml_to_edit = EXTENSIONS_TEMPLATE

    # Parse xml and add <extension />
    root = MD.parseString(xml_to_edit)
    to_append = MD.parseString(CACHE_EXTENSION).documentElement

    document: MD.Element = root.documentElement

    # Append if the extension does not exist
    for extension in document.getElementsByTagName("extension"):
        artifact_id_tag = extension.getElementsByTagName("artifactId").item(0)
        if artifact_id_tag is None:
            continue

        # There is no simple way to retrieve innerText in minidom, so I'm using toxml() instead.
        if "maven-build-cache-extension" in artifact_id_tag.toxml():
            break
    else:
        document.appendChild(to_append)

    # Write back to .mvn/extensions.xml
    extensions_path.write_text(root.toxml())


MAVEN_BUILD_CACHE_CONFIG = """
<?xml version="1.0" encoding="UTF-8"?>
<cache xmlns="http://maven.apache.org/BUILD-CACHE-CONFIG/1.0.0"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:schemaLocation="http://maven.apache.org/BUILD-CACHE-CONFIG/1.0.0 https://maven.apache.org/xsd/build-cache-config-1.0.0.xsd">
<configuration>
<enabled>true</enabled>
<local>
    <maxBuildsCached>10000000</maxBuildsCached>
</local>
</configuration>
<executionControl>
<runAlways>
    <plugins>
        <plugin artifactId="maven-dependency-plugin" />
        <plugin artifactId="maven-install-plugin" />
        <plugin artifactId="flatten-maven-plugin" />
    </plugins>
</runAlways>
</executionControl>
</cache>
""".strip()


def backup(path: Path) -> tuple[Path, bytes | None]:
    if path.exists():
        orig = path.read_bytes()
    else:
        orig = None
    return path, orig


def restore(backup_args: tuple[Path, bytes | None]):
    path, orig = backup_args
    if orig is not None:
        path.write_bytes(orig)
    else:
        path.unlink()


def main():
    # NOTE: it seems like mvn is invoked at the project directory (where ./pom.xml exists).
    # So I'm using .mvn in the current directory.
    Path(".mvn").mkdir(parents=True, exist_ok=True)

    # Create or edit .mvn/extensions.xml
    extension_path = Path(".mvn/extensions.xml")
    cache_config_path = Path(".mvn/maven-build-cache-config.xml")

    # Backup and write
    backups = [
        backup(extension_path),
        backup(cache_config_path),
    ]
    write_extension_config(extension_path)

    cache_config_path.write_text(MAVEN_BUILD_CACHE_CONFIG)

    try:
        # Forward to mvn
        retcode = subprocess.call(sys.argv, executable=find_real_mvn())
    finally:
        # Restore
        for backup_args in backups:
            restore(backup_args)

    exit(retcode)


if __name__ == "__main__":
    main()
