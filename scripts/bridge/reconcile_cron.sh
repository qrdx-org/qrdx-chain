#!/usr/bin/env bash
# Run the custodian's reconcile on a schedule and publish the result to Prometheus through
# node_exporter's textfile collector: qrdx_custodian_reconcile_alarms (0 when every release and
# refund matches QRDX's records). docker/alert-rules.yml pages on anything above 0.
#
#   */10 * * * *  QRDX_RPCS="http://my-node:3007/rpc http://other:3007/rpc" \
#                 SOURCE_RPC=https://arb1.example/rpc CHAIN_ID=42161 LOCKBOX=0x… FROM_BLOCK=123 \
#                 TEXTFILE_DIR=/var/lib/node_exporter/textfile \
#                 /opt/qrdx/scripts/bridge/reconcile_cron.sh
set -euo pipefail

: "${QRDX_RPCS:?space-separated QRDX node /rpc URLs}"
: "${SOURCE_RPC:?the source chain's RPC URL}"
: "${CHAIN_ID:?the source chain's id}"
: "${LOCKBOX:?the lockbox address}"
: "${FROM_BLOCK:?the lockbox's deployment block}"
: "${TEXTFILE_DIR:?node_exporter's textfile directory}"

here="$(cd "$(dirname "$0")" && pwd)"
args=()
for url in ${QRDX_RPCS}; do args+=(--qrdx-rpc "${url}"); done

status=0
out="$(python3 "${here}/custodian.py" reconcile "${args[@]}" --rpc "${SOURCE_RPC}" \
    --chain-id "${CHAIN_ID}" --lockbox "${LOCKBOX}" --from-block "${FROM_BLOCK}" 2>&1)" || status=$?
alarms="$(printf '%s\n' "${out}" | grep -c '^ALARM' || true)"
if [ "${status}" -ne 0 ] && [ "${alarms}" -eq 0 ]; then
    alarms=1  # the check itself failed (refused, unreachable): that is an alarm too
fi
printf '%s\n' "${out}" | logger -t qrdx-reconcile 2>/dev/null || true

tmp="$(mktemp "${TEXTFILE_DIR}/.qrdx_reconcile.XXXXXX")"
cat > "${tmp}" <<METRICS
# HELP qrdx_custodian_reconcile_alarms Alarms from the lockbox custodian's last reconcile.
# TYPE qrdx_custodian_reconcile_alarms gauge
qrdx_custodian_reconcile_alarms{chain="${CHAIN_ID}"} ${alarms}
qrdx_custodian_reconcile_last_run_seconds{chain="${CHAIN_ID}"} $(date +%s)
METRICS
mv "${tmp}" "${TEXTFILE_DIR}/qrdx_reconcile_${CHAIN_ID}.prom"
exit "${status}"
