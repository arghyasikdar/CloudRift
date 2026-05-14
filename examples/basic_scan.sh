#!/usr/bin/env bash
set -euo pipefail

cloudrift example.com --provider aws --threads 20 --timeout 6
