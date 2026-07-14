#!/usr/bin/env bash
#
# Kubernetes RBAC Audit (bash/macOS port of audit.py).
#
# Scans exported RBAC objects (roles, cluster roles, and their bindings) for
# permissions that are commonly abused for privilege escalation or data access,
# then reports which subjects (users, groups, service accounts) actually hold
# those permissions through a binding.
#
# The only requirement is jq (a single self-contained binary):  brew install jq
#
# Export the objects first, e.g.:
#   kubectl get roles --all-namespaces -o json        > roles.json
#   kubectl get rolebindings --all-namespaces -o json > rolebindings.json
#   kubectl get clusterroles -o json                  > clusterroles.json
#   kubectl get clusterrolebindings -o json           > clusterrolebindings.json
#
# Usage:
#   ./audit.sh --roles roles.json --roleBindings rolebindings.json \
#              --clusterRoles clusterroles.json --clusterRoleBindings clusterrolebindings.json
#
# Any combination of the four files is accepted (at least one of
# --roles / --clusterRoles). Exit codes: 0 = clean, 1 = findings, 2 = usage/file error.

set -euo pipefail

prog="$(basename "$0")"

usage() {
    cat >&2 <<EOF
Usage: $prog [--roles FILE] [--roleBindings FILE] [--clusterRoles FILE] [--clusterRoleBindings FILE]

At least one of --roles or --clusterRoles is required.
Requires jq (brew install jq). Set NO_COLOR=1 to disable colour.
EOF
}

roles=/dev/null
rbindings=/dev/null
croles=/dev/null
crbindings=/dev/null
have_roles=false
have_croles=false
have_bindings=false

need_value() {
    # $1 = option name, $2 = value (may be unset)
    if [ -z "${2:-}" ]; then
        echo "error: $1 requires a file argument" >&2
        exit 2
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        --roles)                need_value "$1" "${2:-}"; roles="$2";      have_roles=true;    shift 2 ;;
        --roleBindings)         need_value "$1" "${2:-}"; rbindings="$2";  have_bindings=true; shift 2 ;;
        --clusterRoles)         need_value "$1" "${2:-}"; croles="$2";     have_croles=true;   shift 2 ;;
        --clusterRoleBindings)  need_value "$1" "${2:-}"; crbindings="$2"; have_bindings=true; shift 2 ;;
        -h|--help)              usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required but was not found. Install it with: brew install jq" >&2
    exit 2
fi

if ! $have_roles && ! $have_croles; then
    echo "error: provide at least one of --roles or --clusterRoles (bindings alone have nothing to check against)." >&2
    exit 2
fi

validate() {
    # $1 = path
    local path="$1"
    [ "$path" = /dev/null ] && return 0
    if [ ! -f "$path" ]; then
        echo "error: file not found: $path" >&2
        exit 2
    fi
    if ! jq empty "$path" >/dev/null 2>&1; then
        echo "error: $path is not valid JSON (re-export or re-encode as UTF-8)." >&2
        exit 2
    fi
    if ! jq -e 'has("items")' "$path" >/dev/null 2>&1; then
        echo "error: $path does not look like 'kubectl get ... -o json' output (missing top-level 'items')." >&2
        exit 2
    fi
}

validate "$croles"
validate "$roles"
validate "$crbindings"
validate "$rbindings"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then use_color=true; else use_color=false; fi
if $have_bindings; then bindings_loaded=true; else bindings_loaded=false; fi

# --- jq: evaluate rules and correlate bindings -> model (array of role records) ---
EVAL_PROGRAM=$(cat <<'JQ'
def isDefault($name):
  ($name|startswith("system:")) or ($name|startswith("kubernetes-"))
  or ((["edit","admin","cluster-admin","aws-node"]|index($name)) != null);

def evalRule($res; $vrb):
  []
  # full cluster-admin: every verb on every resource
  + (if (($res|index("*")) != null) and (($vrb|index("*")) != null)
     then [{severity:"CRITICAL", issue:"full admin: all verbs on all resources ('*'/'*')"}] else [] end)
  # a specific dangerous verb against every resource ('*')
  + (if ($res|index("*")) != null then
       ((["delete","deletecollection","create","impersonate","list","get"]
         | map(select(. as $x | ($vrb|index($x)) != null)) | .[0]) as $v
        | if $v != null then
            [{severity:(if (["delete","deletecollection","create","impersonate"]|index($v)) != null then "HIGH" else "MEDIUM" end),
              issue:"can '\($v)' ANY resource (wildcard '*')"}]
          else [] end)
     else [] end)
  # any verb ('*') on a security-sensitive resource
  + (if ($vrb|index("*")) != null then
       ((["secrets","configmaps","pods","deployments","daemonsets","statefulsets","replicationcontrollers","replicasets","cronjobs","jobs","roles","clusterroles","rolebindings","clusterrolebindings","users","groups"]
         | map(select(. as $x | ($res|index($x)) != null)) | .[0]) as $h
        | if $h != null then [{severity:"HIGH", issue:"can perform ANY verb on '\($h)'"}] else [] end)
     else [] end)
  # read access to secrets / configmaps
  + (if (($res|index("secrets")) != null) and ((($vrb|index("*"))!=null) or (($vrb|index("get"))!=null) or (($vrb|index("list"))!=null))
     then [{severity:"HIGH", issue:"can read secrets"}] else [] end)
  + (if (($res|index("configmaps")) != null) and ((($vrb|index("*"))!=null) or (($vrb|index("get"))!=null) or (($vrb|index("list"))!=null))
     then [{severity:"MEDIUM", issue:"can read configmaps"}] else [] end)
  # privilege escalation via creating roles or bindings
  + ((["clusterrolebindings","rolebindings","clusterroles","roles"] | map(select(. as $x | ($res|index($x))!=null)) | .[0]) as $pe
     | if ($pe != null) and ((($vrb|index("create"))!=null) or (($vrb|index("*"))!=null))
       then [{severity:"HIGH", issue:"can create '\($pe)' (privilege escalation)"}] else [] end)
  # creating / updating pod-spawning workloads
  + ((["pods","deployments","daemonsets","statefulsets","replicationcontrollers","replicasets","jobs","cronjobs"] | map(select(. as $x | ($res|index($x))!=null)) | .[0]) as $sp
     | if $sp != null then
         (if ($vrb|index("create")) != null then [{severity:"HIGH", issue:"can create '\($sp)' (schedules arbitrary pods -> node/secret access)"}]
          elif ($vrb|index("update")) != null then [{severity:"MEDIUM", issue:"can update '\($sp)'"}]
          else [] end)
       else [] end)
  # pod subresources used for shell access into running workloads
  + (if (($res|index("pods/exec"))!=null) and ((($vrb|index("*"))!=null) or (($vrb|index("create"))!=null) or (($vrb|index("get"))!=null))
     then [{severity:"HIGH", issue:"can exec into pods"}] else [] end)
  + (if (($res|index("pods/attach"))!=null) and ((($vrb|index("*"))!=null) or (($vrb|index("create"))!=null) or (($vrb|index("get"))!=null))
     then [{severity:"HIGH", issue:"can attach to running pods"}] else [] end);

def dedup: reduce .[] as $f ([]; if any(.[]; . == $f) then . else . + [$f] end);

def scanRoles($items; $kind):
  [ $items[]
    | (.metadata.name) as $name
    | select($name != null and ((isDefault($name)) | not))
    | (if $kind == "Role" then (.metadata.namespace // "") else "" end) as $ns
    | (.rules // []) as $rules
    | { kind:$kind, namespace:$ns, name:$name,
        findings: ( [ $rules[]
                      | select(.resources != null and .verbs != null)
                      | evalRule(.resources; .verbs) | .[] ] | dedup ) }
    | select((.findings|length) > 0) ];

def keyOf: "\(.kind)|\(.namespace)|\(.name)";

def bindingSubjects($items; $bindKind):
  [ $items[]
    | (.metadata.name // "<unknown>") as $bn
    | (.metadata.namespace // "") as $bns
    | (.roleRef) as $ref
    | select($ref != null and ($ref.name != null) and (.subjects != null))
    # a RoleBinding may reference a Role in its own namespace or a cluster-wide
    # ClusterRole; a ClusterRoleBinding only the latter.
    | (if $ref.kind == "ClusterRole" then {kind:"ClusterRole", namespace:"", name:$ref.name}
       elif $ref.kind == "Role" then {kind:"Role", namespace:$bns, name:$ref.name}
       else null end) as $target
    | select($target != null)
    | .subjects[] | select(.name != null)
    | { targetKey:($target|keyOf), subKind:(.kind // "?"), subName:.name,
        subNs:(.namespace // ""), bindKind:$bindKind, bindName:$bn } ];

(scanRoles(($cr[0].items // []); "ClusterRole") + scanRoles(($r[0].items // []); "Role")) as $rolesAll
| (bindingSubjects(($crb[0].items // []); "ClusterRoleBinding") + bindingSubjects(($rb[0].items // []); "RoleBinding")) as $atts
| [ $rolesAll[]
    | . as $role
    | ($role|keyOf) as $k
    | $role + { subjects: [ $atts[] | select(.targetKey == $k) ] } ]
JQ
)

# --- jq: render the model (input) into a coloured report ---
RENDER_PROGRAM=$(cat <<'JQ'
def C($n): if $useColor then "[\($n)m" else "" end;
def sevOrder($s): if $s=="CRITICAL" then 0 elif $s=="HIGH" then 1 else 2 end;
def sevColor($s): if $s=="CRITICAL" then C("1;31") elif $s=="HIGH" then C("31") else C("33") end;
def pad($s): (8 - ($s|length)) as $p | $s + (if $p > 0 then (" " * $p) else "" end);

. as $roles
| ($roles | length) as $total
| ($roles | map(select((.subjects|length) > 0)) | length) as $exposedCount
| ($roles | map([.findings[].severity] | map(sevOrder(.)) | min)) as $worsts
| ($worsts | map(select(. == 0)) | length) as $crit
| ($worsts | map(select(. == 1)) | length) as $high
| ($worsts | map(select(. == 2)) | length) as $med
| ( [ (C("1") + ("=" * 64) + C("0")),
      (C("1") + " Kubernetes RBAC Audit - findings" + C("0")),
      (C("1") + ("=" * 64) + C("0")) ]
    + ( if $total == 0 then
          [ C("32") + "[ok]" + C("0") + " No risky roles found." ]
        else
          [ "\($total) risky role(s): \(sevColor("CRITICAL"))\($crit) critical\(C("0")), \(sevColor("HIGH"))\($high) high\(C("0")), \(sevColor("MEDIUM"))\($med) medium\(C("0"))." ]
          + ( if $bindingsLoaded then
                [ "\(C("1;31"))\($exposedCount)\(C("0")) of them are \(C("1;31"))EXPOSED\(C("0")) (bound to a subject) - fix these first." ]
              else
                [ C("33") + "[note]" + C("0") + " No binding files supplied; cannot tell which risky roles are actually granted to anyone." ]
              end )
          + ( $roles
              | sort_by([ (if (.subjects|length) > 0 then 0 else 1 end),
                          ([.findings[].severity] | map(sevOrder(.)) | min),
                          .kind, .name ])
              | map(
                  . as $r
                  | (($r.subjects|length) > 0) as $exposed
                  | (if $r.namespace != "" then "\($r.kind) \($r.namespace)/\($r.name)" else "\($r.kind) \($r.name)" end) as $loc
                  | (if $exposed then C("1;31") + "[EXPOSED]" + C("0")
                     elif $bindingsLoaded then C("33") + "[unbound]" + C("0")
                     else C("33") + "[risky]" + C("0") end) as $tag
                  | ( [ "", "\($tag) \(C("1"))\($loc)\(C("0"))" ]
                      + ( $r.findings | sort_by(sevOrder(.severity))
                          | map("    \(sevColor(.severity))\(pad(.severity))\(C("0")) \(.issue)") )
                      + ( $r.subjects
                          | map( (if .subNs != "" then "\(.subNs)/\(.subName)" else .subName end) as $who
                                 | "      \(C("36"))-> granted to\(C("0")) \(.subKind): \($who) (via \(.bindKind) \(.bindName))" ) ) ) )
              | add )
          + [ "" ]
        end ) )
| .[]
JQ
)

model="$(jq -n \
    --slurpfile cr "$croles" \
    --slurpfile r "$roles" \
    --slurpfile crb "$crbindings" \
    --slurpfile rb "$rbindings" \
    "$EVAL_PROGRAM")"

printf '%s\n' "$model" | jq -r \
    --argjson useColor "$use_color" \
    --argjson bindingsLoaded "$bindings_loaded" \
    "$RENDER_PROGRAM"

count="$(printf '%s\n' "$model" | jq 'length')"
if [ "$count" -gt 0 ]; then
    exit 1
fi
exit 0
