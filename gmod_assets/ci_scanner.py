import os
import glob
import subprocess
import sys

DECOMPILER_PATH = "./decompiler_core.exe"
TARGET_DIR = "./gmod ios 2"
OUTPUT_DIR = "./xcode_ready_src"

if not os.path.exists(DECOMPILER_PATH):
    print("[-] Error: Compiled decompiler_core.exe backend not found.")
    sys.exit(1)

os.makedirs(OUTPUT_DIR, exist_ok=True)

print(f"[*] Commencing global cloud scan in target tree: {TARGET_DIR}")

# 1. Grab ALL .dll files across every deep subfolder directory tree
dll_pattern = os.path.join(TARGET_DIR, "**", "*.dll")
dll_files = glob.glob(dll_pattern, recursive=True)

# 2. Specifically look for and lock onto gmod.exe
gmod_exe_path = None
exe_pattern = os.path.join(TARGET_DIR, "**", "*.exe")
all_exes = glob.glob(exe_pattern, recursive=True)

for exe in all_exes:
    if os.path.basename(exe).lower() == "gmod.exe":
        gmod_exe_path = exe
        break

# Combine our targets: All found DLLs + gmod.exe exclusively
target_binaries = dll_files
if gmod_exe_path:
    print(f"[+] Found core binary target: {gmod_exe_path}")
    target_binaries.append(gmod_exe_path)
else:
    print("[-] Warning: gmod.exe not detected in the current directory branch scan.")

if not target_binaries:
    print("[-] Zero target binary files located in the repository environment.")
    sys.exit(0)

print(f"[+] Operational queue populated with {len(target_binaries)} engine targets.")

recovered_cpp_files = []

# Process all selected binaries through the C decompiler core loop
for bin_path in target_binaries:
    file_name = os.path.basename(bin_path)
    clean_name = os.path.splitext(file_name)[0].replace(".", "_").replace("-", "_")
    output_file_name = f"{clean_name}_decompiled.cpp"
    output_path = os.path.join(OUTPUT_DIR, output_file_name)
    
    print(f"[*] Extracting Logic: {file_name} -> {output_file_name}")
    
    try:
        result = subprocess.run([DECOMPILER_PATH, bin_path], capture_output=True, text=True, check=True)
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("// =========================================================\n")
            f.write(f"// Recovered Source Structuring: {file_name}\n")
            f.write("// Target Compatibility: Apple Xcode Project Framework\n")
            f.write("// =========================================================\n\n")
            f.write(result.stdout)
            
        recovered_cpp_files.append(output_file_name)
    except subprocess.CalledProcessError as e:
        print(f"[-] Code generation skipped on {file_name}: {e.stderr}")

# 3. Dynamic Generation of the CMake blueprint file to auto-generate the Xcode Project
print("[*] Generating Xcode Project Build Blueprint (CMakeLists.txt)...")
cmake_path = os.path.join(OUTPUT_DIR, "CMakeLists.txt")

with open(cmake_path, "w", encoding="utf-8") as cm:
    cm.write("cmake_minimum_required(VERSION 3.10)\n")
    cm.write("project(GModIOSFramework CXX)\n\n")
    cm.write("set(CMAKE_CXX_STANDARD 17)\n\n")
    cm.write("add_library(GModCoreFramework SHARED\n")
    for cpp_file in recovered_cpp_files:
        cm.write(f"    {cpp_file}\n")
    cm.write(")\n")

print("[+] Cloud conversion engine complete. Xcode compilation blueprint created successfully.")
