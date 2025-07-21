# ExtensiveRoleCheck

`ExtensiveRoleCheck` is a Python tool that scans the Kubernetes RBAC for risky roles. The tool is a part of the "Kubernetes Pentest Methdology" blog post series.
```
usage: ExtensiveRoleCheck.py [-h] [--clusterRoles CLUSTERROLES] [--roles ROLES] [--roleBindings ROLEBINDINGS] [--clusterRoleBindings CLUSTERROLEBINDINGS]
```

This tool has been modified and updated by Jake.

## Overview

**Status**: Alpha

The RBAC API is a set of roles that administrators can configure to limit access to the Kubernetes resources. The *ExtensiveRoleCheck* automates the searching process and outputs the risky roles and rolebindings found in the RBAC API. 

## Requirements:
*ExtensiveRoleCheck* requires python3

*ExtensiveRoleCheck* works in offline mode. This means that you should first export the following `JSON` from your Kubernetes cluster configuration:

 - Roles 
 - ClusterRoles 
 - RoleBindings 
 - ClusterRoleBindings

To export those files you will need access permissions in the Kubernetes cluster. To export them, you might use the following commands:

**Export RBAC Roles:**
```
kubectl get roles --all-namespaces -o json > roles.json
```
**Export RBAC ClusterRoles:**
```
kubectl get clusterroles -o json > clusterroles.json
```
**Export RBAC RolesBindings:**
```
kubectl get rolebindings --all-namespaces -o json > rolebindings.json
```
**Export RBAC Cluster RolesBindings:**
```
kubectl get clusterrolebindings -o json > clusterrolebindings.json
```

## Example & Output:
**Usage**
```
python ExtensiveRoleCheck.py --clusterRoles clusterroles.json --roles Roles.json --roleBindings rolebindings.json --clusterRoleBindings clusterrolebindings.json
```
![Output example](https://github.com/cyberark/kubernetes-rbac-audit/blob/master/output-example.png)

##  Maintainers:
Or Ida: or.ida@cyberark.com
