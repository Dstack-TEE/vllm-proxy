#!/bin/bash

.venv_missing_message() {
  cat <<'EOF' >&2
Missing `.venv`.

Create one and install deps, e.g.:
  UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never uv venv -p python3
  uv pip install --python .venv/bin/python -r requirements.txt -r test-requirements.txt
EOF
}

if [ ! -f ".venv/bin/activate" ]; then
  .venv_missing_message
  exit 1
fi

. .venv/bin/activate
PYTHONPATH=src python -m pytest tests/ -v "$@"
