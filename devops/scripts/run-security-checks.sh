#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../../backend"

pytest
bandit -r app
