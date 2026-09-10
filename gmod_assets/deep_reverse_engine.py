import os
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path.cwd()
ANALYSIS = ROOT / "analysis"
IOS_PORT = ROOT / "ios_port"

BINARY_EXTENSIONS = {".exe", ".dll"}

# Avoid recursively analyzing our own generated output.
EXCLUDED_DIRS = {
    ".git",
    "analysis",
    "ios_port",
}


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_command(
    command: list[str],
    output_file: Path,
    timeout: int = 3600,
) -> bool:
    output_file.parent.mkdir(parents=True, exist_ok=True)

    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )

        output_file.write_text(
            result.stdout,
            encoding="utf-8",
            errors="replace",
        )

        return result.returncode == 0

    except subprocess.TimeoutExpired as exc:
        output_file.write_text(
            f"COMMAND TIMED OUT\n\n{exc}\n",
            encoding="utf-8",
        )
        return False


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def find_binaries() -> list[Path]:
    results: list[Path] = []

    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue

        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue

        if path.suffix.lower() in BINARY_EXTENSIONS:
            results.append(path)

    return sorted(results)


def safe_output_name(path: Path) -> str:
    return (
        path.relative_to(ROOT)
        .as_posix()
        .replace("/", "__")
        .replace("\\", "__")
    )


def analyze_binary(binary: Path) -> None:
    name = safe_output_name(binary)
    out = ANALYSIS / name
    out.mkdir(parents=True, exist_ok=True)

    print(f"[+] Analyzing {binary}")

    metadata = {
        "file": binary.relative_to(ROOT).as_posix(),
        "size": binary.stat().st_size,
        "sha256": sha256_file(binary),
        "suffix": binary.suffix.lower(),
        "tools_available": {
            "strings": tool_exists("strings"),
            "objdump": tool_exists("objdump"),
            "r2": tool_exists("r2"),
            "ghidra": bool(
                os.environ.get("GHIDRA_HOME")
                and Path(os.environ["GHIDRA_HOME"]).exists()
            ),
        },
    }

    (out / "metadata.json").write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    # ---------------------------------------------------------
    # 1. PE parsing
    # ---------------------------------------------------------

    try:
        import pefile

        pe = pefile.PE(str(binary))

        data = {
            "machine": hex(pe.FILE_HEADER.Machine),
            "characteristics": hex(pe.FILE_HEADER.Characteristics),
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "sections": [],
            "imports": [],
            "exports": [],
        }

        for section in pe.sections:
            data["sections"].append(
                {
                    "name": section.Name.decode(
                        "utf-8",
                        errors="replace",
                    ).rstrip("\x00"),
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                }
            )

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(
                    "utf-8",
                    errors="replace",
                )

                for imported in entry.imports:
                    name = (
                        imported.name.decode(
                            "utf-8",
                            errors="replace",
                        )
                        if imported.name
                        else None
                    )

                    data["imports"].append(
                        {
                            "dll": dll_name,
                            "name": name,
                            "address": hex(imported.address),
                        }
                    )

        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exported in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                data["exports"].append(
                    {
                        "name": (
                            exported.name.decode(
                                "utf-8",
                                errors="replace",
                            )
                            if exported.name
                            else None
                        ),
                        "address": hex(exported.address),
                        "ordinal": exported.ordinal,
                    }
                )

        (out / "pe.json").write_text(
            json.dumps(data, indent=2),
            encoding="utf-8",
        )

    except Exception as exc:
        (out / "pe_error.txt").write_text(
            str(exc),
            encoding="utf-8",
        )

    # ---------------------------------------------------------
    # 2. Strings
    # ---------------------------------------------------------

    if tool_exists("strings"):
        run_command(
            [
                "strings",
                "-a",
                "-n",
                "4",
                str(binary),
            ],
            out / "strings.txt",
            timeout=1800,
        )

    # ---------------------------------------------------------
    # 3. GNU objdump
    # ---------------------------------------------------------

    if tool_exists("objdump"):
        run_command(
            [
                "objdump",
                "-x",
                str(binary),
            ],
            out / "objdump_headers.txt",
        )

        run_command(
            [
                "objdump",
                "-d",
                str(binary),
            ],
            out / "objdump_disassembly.txt",
            timeout=3600,
        )

    # ---------------------------------------------------------
    # 4. radare2
    # ---------------------------------------------------------

    if tool_exists("r2"):
        run_command(
            [
                "r2",
                "-q",
                "-c",
                "aaa; iI; iE; iz; afl",
                str(binary),
            ],
            out / "radare2_inventory.txt",
            timeout=3600,
        )

    # ---------------------------------------------------------
    # 5. Ghidra headless
    # ---------------------------------------------------------

    ghidra_home = os.environ.get("GHIDRA_HOME")

    if ghidra_home:
        analyze_headless = (
            Path(ghidra_home)
            / "support"
            / "analyzeHeadless"
        )

        if analyze_headless.exists():
            ghidra_dir = out / "ghidra_project"
            ghidra_dir.mkdir(parents=True, exist_ok=True)

            project_name = "BinaryAnalysis"

            run_command(
                [
                    str(analyze_headless),
                    str(ghidra_dir),
                    project_name,
                    "-import",
                    str(binary.resolve()),
                    "-deleteProject",
                ],
                out / "ghidra.log",
                timeout=7200,
            )


def generate_ios_scaffold() -> None:
    source_dir = IOS_PORT / "Sources"
    include_dir = IOS_PORT / "include"

    source_dir.mkdir(parents=True, exist_ok=True)
    include_dir.mkdir(parents=True, exist_ok=True)

    cmake = """\
cmake_minimum_required(VERSION 3.28)

project(BinaryPortWorkspace LANGUAGES C CXX OBJC OBJCXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE PORT_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/*.mm"
    "${CMAKE_CURRENT_SOURCE_DIR}/Sources/*.m"
)

add_library(binary_port STATIC
    ${PORT_SOURCES}
)

target_include_directories(binary_port
    PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_compile_definitions(binary_port
    PRIVATE
    TARGET_OS_IOS=1
)
"""

    (IOS_PORT / "CMakeLists.txt").write_text(
        cmake,
        encoding="utf-8",
    )

    report = """\
# iOS Porting Workspace

This directory is generated from binary-analysis results.

The analysis does NOT recreate the original source tree.

Functions dependent on Windows, Direct3D, Win32, Windows
filesystem APIs, Windows threading, or other platform-specific
interfaces must be implemented using iOS-compatible APIs.

Suggested migration stages:

1. Identify portable algorithms.
2. Identify platform-specific dependencies.
3. Rewrite platform layers.
4. Replace Windows graphics dependencies with the target
   iOS graphics stack.
5. Build and resolve compile/link errors.
6. Test each subsystem independently.

Generated automatically by deep_reverse.py.
"""

    (IOS_PORT / "PORTING_REPORT.md").write_text(
        report,
        encoding="utf-8",
    )


def write_summary(binaries: list[Path]) -> None:
    summary = {
        "binary_count": len(binaries),
        "binaries": [
            {
                "path": p.relative_to(ROOT).as_posix(),
                "size": p.stat().st_size,
                "sha256": sha256_file(p),
            }
            for p in binaries
        ],
    }

    (ANALYSIS / "inventory.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )


def main() -> int:
    ANALYSIS.mkdir(parents=True, exist_ok=True)

    binaries = find_binaries()

    print("=" * 70)
    print("DEEP BINARY ANALYSIS")
    print("=" * 70)
    print(f"Found {len(binaries)} EXE/DLL files.")

    for binary in binaries:
        analyze_binary(binary)

    write_summary(binaries)
    generate_ios_scaffold()

    print("=" * 70)
    print("ANALYSIS COMPLETE")
    print(f"Reports: {ANALYSIS}")
    print(f"iOS workspace: {IOS_PORT}")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())