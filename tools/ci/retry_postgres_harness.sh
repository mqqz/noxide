#!/usr/bin/env bash
# Run a PostgreSQL application harness; on failure retry once with a fresh database.
# Shared runners can miss host cleanup deadlines, which correctly fail closed with
# Busy. The first output stays in the log and a second failure fails the job.
# usage: retry_postgres_harness.sh DATABASE OUTPUT -- HARNESS_COMMAND...
set -euo pipefail
database=$1 output=$2
shift 3
for attempt in 1 2; do
  psql "$NOXIDE_TEST_POSTGRES" -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${database}_${attempt}"
  if "$@" --output "${output}-${attempt}" --postgres "${NOXIDE_TEST_POSTGRES%/*}/${database}_${attempt}"; then
    exit 0
  fi
  echo "::warning::${database} harness attempt ${attempt} failed"
done
exit 1
