    #!/bin/bash
    set -euo pipefail

    HIVE="/data/NTUSER.DAT"
    OUT="/data/NTUSER_patched.DAT"
    # Default flag; can override with -e FLAG when running container
    FLAG="${FLAG:-CTF{shellbag_base64_hidden}}"

    # full path: ROOT_NAME\Software\Microsoft\Windows\CurrentVersion\Run
    echo "Looking for hive at: ${HIVE}"
    if [ ! -f "${HIVE}" ]; then
      echo "ERROR: NTUSER.DAT not found at ${HIVE}. Mount your file into /data and retry."
      exit 2
    fi

    # compute base64 of FLAG (no newlines)
    B64=$(python3 - <<PY
import os, base64
f = os.environ.get('FLAG', "CTF{shellbag_base64_hidden}")
b = base64.b64encode(f.encode()).decode().replace('\n','')
print(b)
PY
)

    echo "Base64 flag to insert: ${B64}"

    # prepare hivexsh command file
    CMDFILE="/tmp/hivex_cmds.txt"
    : > "${CMDFILE}"

    echo "cd Software" >> "${CMDFILE}"
    echo "cd Microsoft" >> "${CMDFILE}"
    echo "cd Windows" >> "${CMDFILE}"
    echo "cd CurrentVersion" >> "${CMDFILE}"
    echo "cd Run" >> "${CMDFILE}"
    echo "setval 1" >> "${CMDFILE}"
    echo "Persist_agent_B64" >> "${CMDFILE}"
    echo "string:${B64}" >> "${CMDFILE}"
    echo "commit ${OUT}" >> "${CMDFILE}"
    echo "quit" >> "${CMDFILE}"

    echo "=== hivexsh commands ==="
    sed -n '1,200p' "${CMDFILE}" || true

    # execute hivexsh reading commands from file
    hivexsh -w "${HIVE}" < "${CMDFILE}"

    echo "Patched hive written to ${OUT}"
    echo "Done."
