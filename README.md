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

The roles, role bindings, cluster roles, and cluster role bindings must be exported with the following commands:

```
kubectl get roles --all-namespaces -o json > roles.json
kubectl get rolebindings --all-namespaces -o json > rolebindings.json
kubectl get clusterroles -o json > clusterroles.json
kubectl get clusterrolebindings -o json > clusterrolebindings.json
```

---
<h4>Usage</h4>

```
PS D:\Kubernetes-RBAC-Audit> python3 audit.py --roles roles.json --roleBindings rolebindings.json --clusterroles clusterRoles.json --clusterRoleBindings clusterrolebindings.json
[ClusterRole] cluster-pod-creator has permission to create pods
[ClusterRole] cluster-secret-reader has permission to list pods
...
```
