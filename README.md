<h3>📝 Kubernetes RBAC Audit</h3>
<p>
  <a href="https://kubernetes.io/docs/reference/access-authn-authz/rbac">Documentation</a>
</p>

---
✨ Kubernetes RBAC is a key security control to ensure that cluster users and workloads have only the access to resources required to execute their roles.

Process risky roles and role bindings found in the RBAC API.

See [here](https://github.com/cyberark/kubernetes-rbac-audit) for the original code. Updated and maintained by Jake as the source was forgotton.

---
<h4>Requirements</h4>

Two interchangeable implementations are provided — use whichever suits your box:

- **`audit.py`** (cross-platform) — needs Python 3 and `colorama`:
  ```
  pip install -r requirements.txt
  ```
- **`audit.sh`** (bash / macOS) — needs only [`jq`](https://jqlang.github.io/jq/):
  ```
  brew install jq
  ```

Both take the same arguments and produce identical output.

The roles, role bindings, cluster roles, and cluster role bindings should be exported with the following commands (supply whichever you have — at least one of roles/clusterroles is required):

```
kubectl get roles --all-namespaces -o json > roles.json
kubectl get rolebindings --all-namespaces -o json > rolebindings.json
kubectl get clusterroles -o json > clusterroles.json
kubectl get clusterrolebindings -o json > clusterrolebindings.json
```

---
<h4>Usage</h4>

```
PS D:\Kubernetes-RBAC-Audit> python3 audit.py --roles roles.json --roleBindings rolebindings.json --clusterRoles clusterroles.json --clusterRoleBindings clusterrolebindings.json
================================================================
 Kubernetes RBAC Audit - findings
================================================================
4 risky role(s): 1 critical, 2 high, 1 medium.
3 of them are EXPOSED (bound to a subject) - fix these first.

[EXPOSED] ClusterRole cluster-admin-ish
    CRITICAL full admin: all verbs on all resources ('*'/'*')
      -> granted to User: alice (via ClusterRoleBinding crb1)

[EXPOSED] Role dev/pod-exec
    HIGH     can exec into pods
    HIGH     can create 'pods' (schedules arbitrary pods -> node/secret access)
      -> granted to ServiceAccount: dev/builder (via RoleBinding rb1)

[unbound] ClusterRole secret-reader
    HIGH     can read secrets
```

Findings are grouped by role, ranked by severity (CRITICAL/HIGH/MEDIUM), and roles that are actually bound to a subject are flagged `[EXPOSED]` and listed first. Bindings are matched to roles by both `roleRef` kind and namespace, so a `Role` and a `ClusterRole` that share a name are never confused.

On macOS/Linux the bash port takes the same flags:

```
./audit.sh --roles roles.json --roleBindings rolebindings.json --clusterRoles clusterroles.json --clusterRoleBindings clusterrolebindings.json
```

Any combination of the four files is accepted (at least one of roles/clusterroles). Both tools exit `0` when nothing risky is found, `1` when there are findings (useful in CI), and `2` on a usage or file error.

---
<h4>Markdown report</h4>

Add `--markdown FILE` to either tool to also write a pentest-ready Markdown report alongside the console output:

```
python3 audit.py --roles roles.json --roleBindings rolebindings.json --clusterRoles clusterroles.json --clusterRoleBindings clusterrolebindings.json --markdown rbac-findings.md
./audit.sh   --roles roles.json --roleBindings rolebindings.json --clusterRoles clusterroles.json --clusterRoleBindings clusterrolebindings.json --markdown rbac-findings.md
```

The report has a summary line, an **Exposed grants (Affects)** table (one row per subject → role grant, ready to drop into a finding's "Affects" section), and a separate **Unbound risky roles** table for latent roles that no subject currently holds. Both tools produce the same Markdown.
