# Lua Bytecodes and Extraction Tools

This folder contains:

- Lua bytecodes extracted from Microsoft Defender definition files.
- CSV files with exclusions.
- Software required to extract and decompile Lua bytecodes.

> **Note**
> The Lua bytecodes included in this folder were extracted in **September 2026**. Their relevance decreases over time as Microsoft Defender definitions are updated. For the most accurate and up-to-date results, it is recommended to perform the extraction yourself.

## Extraction Instructions

1. Copy the following file from a Windows system:

   ```text
   C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{GUID}\mpasbase.vdm
   ```

2. Place `mpasbase.vdm` in a Linux directory containing:
   - `vdm_lua_extract.py`
   - `luadec`

3. Run the extraction command:

   ```bash
   python3 vdm_lua_extract.py --decompile mpasbase.vdm <folder_name>
   ```

4. The extracted and decompiled Lua bytecodes will be written to the specified output folder.

## Recommendation

Since Defender signatures and embedded Lua scripts change frequently, regenerate the bytecodes from the latest `mpasbase.vdm` whenever possible instead of relying on the archived files in this repository.