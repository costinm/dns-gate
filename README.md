# dns-sync-gcp

External DNS and dns-sync plugin for GCP.

The code is forked and extended from the [external-dns]() project, with standalone manifests, including network policy.
It is intended to be run on Istio ambient/sidecar or another secure network - it does not do its own mTLS or authz.



# Setup

IAM permissions must be set by an admin, see the Makefile (iam) for examples.

PROJECT_ID is the project where the DNS is running, GKE_PROJECT_ID is the project where the GKE cluster running 
dns-sync-gcp is located. For more security it is best to use separate projects for network/dns and workloads, but 
it is simpler to use the same project.


```shell

gcloud projects add-iam-policy-binding projects/${PROJECT_ID} \
      --member "serviceAccount:${GKE_PROJECT_ID}.svc.id.goog[dns-system/default]" \
      --role=roles/dns.admin

```
