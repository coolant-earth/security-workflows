#!/usr/bin/env bash

set -euo pipefail

scan_root="${1:-.}"

if ! repo_root=$(git -C "$scan_root" rev-parse --show-toplevel 2>/dev/null); then
    printf 'security scan: %s is not a Git repository\n' "$scan_root" >&2
    exit 2
fi

finding_count=0

report() {
    local path="$1"
    local message="$2"

    finding_count=$((finding_count + 1))
    printf 'SECURITY FINDING: %s: %s\n' "$path" "$message" >&2
}

# Split high-confidence indicators across shell tokens so this scanner does not
# contain the complete byte strings that it is looking for.
ioc_patterns=(
    'rmcej%''otb%'
    'Cot%3t=''shtP'
    '2857''687'
    '2667''686'
    '1111''436'
    '3896''884'
    'default-configuration.''vercel.app'
    'vscode-settings-bootstrap.''vercel.app'
    'vscode-settings-config.''vercel.app'
    'vscode-bootstrapper.''vercel.app'
    'vscode-load-config.''vercel.app'
    '260120.''vercel.app'
    'tailwindcss-style-''animate'
    'tailwind-main''animation'
    'tailwind-auto''animation'
    'tailwind-animation''based'
    'tailwindcss-typography-''style'
    'tailwindcss-style-''modify'
    'tailwindcss-animate-''style'
    'e9b53a7c-2342-4b15-''b02d-bd8b8f6a03f9'
)

ioc_pattern_file=$(mktemp "${TMPDIR:-/tmp}/repository-security-iocs.XXXXXX")
trap 'rm -f "$ioc_pattern_file"' EXIT
printf '%s\n' "${ioc_patterns[@]}" >"$ioc_pattern_file"

while IFS= read -r -d '' matched_path; do
    report "$matched_path" 'matches a high-confidence malware campaign indicator'
done < <(
    cd "$repo_root"
    git grep -al -z -F -f "$ioc_pattern_file" -- . 2>/dev/null || true
)

while IFS= read -r matched_path; do
    report "$matched_path" 'matches a high-confidence malware campaign indicator'
done < <(
    cd "$repo_root"
    git ls-files -z --others --exclude-standard |
        xargs -0 grep -al -F -f "$ioc_pattern_file" -- 2>/dev/null || true
)

is_javascript_entrypoint() {
    case "$1" in
        *.config.js|*.config.cjs|*.config.mjs|*.config.ts|*/App.js|App.js|*/app.js|app.js)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

scan_javascript_entrypoint() {
    local relative_path="$1"
    local absolute_path="$2"

    if LC_ALL=C awk 'length($0) > 4000 { found = 1; exit } END { exit !found }' "$absolute_path"; then
        report "$relative_path" 'configuration entrypoint contains a line longer than 4,000 bytes'
    fi

    if grep -aEq '(^|[^[:alnum:]_])(eval|Function)[[:space:]]*\(' "$absolute_path"; then
        report "$relative_path" 'configuration entrypoint performs dynamic code evaluation'
    fi

    if grep -aEq '(child_process|node:child_process|process\.binding)' "$absolute_path" &&
       grep -aEq '(https?://|fetch[[:space:]]*\(|XMLHttpRequest|WebSocket)' "$absolute_path"; then
        report "$relative_path" 'configuration entrypoint combines process execution with network access'
    fi

    if grep -aEq "(Buffer\\.from|atob)[[:space:]]*\\([^\\n]*(base64|[\"'][A-Za-z0-9+/]{200,255}={0,2}[\"'])" "$absolute_path" &&
       grep -aEq '(eval|Function|child_process|spawn|exec)' "$absolute_path"; then
        report "$relative_path" 'configuration entrypoint decodes data and executes code'
    fi
}

scan_workflow_or_task() {
    local relative_path="$1"
    local absolute_path="$2"

    if grep -aiEq '(curl|wget).{0,240}\|.{0,80}(bash|sh|zsh|powershell|pwsh)' "$absolute_path"; then
        report "$relative_path" 'downloads content and pipes it directly to a shell'
    fi

    if grep -aiEq '(Invoke-Expression|(^|[^[:alnum:]_])IEX[[:space:]]*\(|FromBase64String)' "$absolute_path"; then
        report "$relative_path" 'contains high-risk PowerShell execution behavior'
    fi

    if grep -qE 'pull_request_target[[:space:]]*:' "$absolute_path" &&
       grep -qE '(github\.event\.pull_request\.head\.(sha|ref)|refs/pull/)' "$absolute_path"; then
        report "$relative_path" 'checks out untrusted pull-request code in a privileged workflow'
    fi
}

scan_lifecycle_scripts() {
    local relative_path="$1"
    local absolute_path="$2"
    local lifecycle_scripts

    if ! command -v jq >/dev/null 2>&1; then
        return
    fi

    lifecycle_scripts=$(jq -r '
        (.scripts // {})
        | to_entries[]
        | select(.key | test("^(preinstall|install|postinstall|prepare)$"))
        | .value
    ' "$absolute_path" 2>/dev/null || true)

    if grep -aiEq '(curl|wget).{0,240}\|.{0,80}(bash|sh|zsh|powershell|pwsh)' <<<"$lifecycle_scripts"; then
        report "$relative_path" 'package lifecycle script downloads content directly into a shell'
    fi

    if grep -aiEq '(git[[:space:]]+push[^\n]*(-f|--force)|temp_auto_push|postcss\.config|eslint\.config|tailwind\.config)' <<<"$lifecycle_scripts"; then
        report "$relative_path" 'package lifecycle script can rewrite Git history or project configuration'
    fi
}

while IFS= read -r -d '' relative_path; do
    absolute_path="$repo_root/$relative_path"

    if [[ ! -f "$absolute_path" ]]; then
        continue
    fi

    case "$relative_path" in
        temp_auto_push.bat|*/temp_auto_push.bat)
            report "$relative_path" 'known force-push propagation artifact'
            ;;
        config.bat)
            report "$relative_path" 'known hidden malware orchestrator filename at repository root'
            ;;
        *.woff|*.woff2)
            font_magic=$(LC_ALL=C dd if="$absolute_path" bs=4 count=1 2>/dev/null || true)
            if [[ "$font_magic" != 'wOFF' && "$font_magic" != 'wOF2' ]]; then
                report "$relative_path" 'font extension does not contain valid WOFF/WOFF2 magic bytes'
            fi
            ;;
    esac

    if is_javascript_entrypoint "$relative_path"; then
        scan_javascript_entrypoint "$relative_path" "$absolute_path"
    fi

    case "$relative_path" in
        .github/workflows/*.yml|.github/workflows/*.yaml|*/.vscode/tasks.json|.vscode/tasks.json)
            scan_workflow_or_task "$relative_path" "$absolute_path"
            ;;
    esac

    case "$relative_path" in
        package.json|*/package.json)
            scan_lifecycle_scripts "$relative_path" "$absolute_path"
            ;;
    esac
done < <(git -C "$repo_root" ls-files -z --cached --others --exclude-standard)

if [[ -f "$repo_root/.gitignore" ]] && grep -qxF 'config.bat' "$repo_root/.gitignore"; then
    report '.gitignore' 'hides a known malware orchestrator filename'
fi

if (( finding_count > 0 )); then
    printf 'security scan failed: %d high-confidence finding(s)\n' "$finding_count" >&2
    exit 1
fi

printf 'security scan passed: no high-confidence repository malware indicators found\n'
