#!/usr/bin/env bash
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
    echo "git is required" >&2
    exit 2
fi

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "${REPO_ROOT}" ]]; then
    echo "Must run inside a git repository" >&2
    exit 2
fi

cd "${REPO_ROOT}"

violations=()

while IFS= read -r -d '' tracked_path; do
    case "${tracked_path}" in
        dist/*)
            violations+=("${tracked_path}")
            continue
            ;;
        nmap)
            violations+=("${tracked_path}")
            continue
            ;;
        *.deb)
            violations+=("${tracked_path}")
            continue
            ;;
        nmap_extended_ts_client/*.tgz)
            violations+=("${tracked_path}")
            continue
            ;;
        nmap_extended_ts_client/node_modules/*|nmap_extended_ts_client/dist/*|nmap_extended_ts_client/dist-tests/*|nmap_extended_ts_client/temp/*)
            violations+=("${tracked_path}")
            continue
            ;;
        service_config.json|service_config.*.json)
            violations+=("${tracked_path}")
            continue
            ;;
    esac
done < <(git ls-files -z)

if [[ ${#violations[@]} -eq 0 ]]; then
    echo "Artifact hygiene check passed."
    exit 0
fi

echo "Artifact hygiene check failed. Forbidden tracked artifacts detected:" >&2
for artifact_path in "${violations[@]}"; do
    echo "  - ${artifact_path}" >&2
done

echo >&2
echo "Remediation:" >&2
echo "  1) Remove tracked artifacts from index (keep local file):" >&2
for artifact_path in "${violations[@]}"; do
    printf '     git rm --cached -- %q\n' "${artifact_path}" >&2
done

echo "  2) Commit the removals and ensure .gitignore covers future outputs." >&2

exit 1
