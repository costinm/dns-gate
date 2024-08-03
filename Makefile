# The build targets allow to build the binary and container image
.PHONY: build

BINARY        ?= dns-gate-gcp
REGISTRY      ?= costinm
REPO_IMAGE         ?= $(REGISTRY)/$(BINARY)

-include ${HOME}/.env.mk

# Ko provides this env
IMAGE_TAG ?= latest

VERSION       ?= $(shell git describe --tags --always --dirty --match "v*")
IMG_PUSH      ?= true
IMG_SBOM      ?= none


PROJECT_ID?=dmeshgate
GKE_PROJECT_ID=costin-asm1
REGION?=us-central1
GCLOUD_USER=$(shell gcloud config get-value account)
GSA="dns-sync@${GKE_PROJECT_ID}.iam.gserviceaccount.com"

push:
	@echo Context: ${BUILD_CONTEXT}
	@echo Image: ${IMAGE_REPO} ${IMAGE}  ${PUSH_IMAGE}
	@echo Tag: ${IMAGE_TAG}

	KO_DOCKER_REPO=${REGISTRY} \
    VERSION=${VERSION} \
      ko build --tags ${IMAGE_TAG} -B --sbom ${IMG_SBOM} \
      --image-label org.opencontainers.image.source="https://github.com/costinm/dns-gate-gcp" \
      --image-label org.opencontainers.image.revision=$(shell git rev-parse HEAD) \
       --push=${IMG_PUSH} .

deploy:
	kubectl create ns dns-system || true
	helm upgrade -i -n dns-system dns-gate-gcp ./manifests/charts/dns-gate --wait \
      --set image.repository=${REGISTRY} --set image.tag=${IMAGE_TAG} --set image.pullPolicy=Always

logs:
	kubectl -n dns-system logs -l app=dns-gate

debug:
	kubectl -n dns-system port-forward service/dns 18080:8080

curl:
	curl -vvv localhost:18080/


curlcr: URL=$(shell  gcloud run services --project ${PROJECT_ID} --region us-central1 describe dns-sync-gcp --format='value(status.address.url)')
curlcr:
	curl -vvv curl -H "Authorization: Bearer $(shell gcloud auth print-identity-token)"   ${URL}/google/


crperm: GCLOUD_USER=$(shell gcloud config get-value account)
crperm:
	gcloud run services add-iam-policy-binding --project ${PROJECT_ID} --region ${REGION} dns-sync-gcp  \
      --member="user:${GCLOUD_USER}" \
      --role='roles/run.invoker'

cr:
	cat manifests/cloudrun.yaml | \
    	DEPLOY="$(shell date +%H%M)" envsubst | \
    gcloud alpha run services --project ${PROJECT_ID} replace -


iam:
	gcloud iam --project ${PROJECT_ID} service-accounts create dns-sync # --display-name dns-default

	gcloud projects add-iam-policy-binding ${PROJECT_ID} \
		--role=roles/dns.admin \
		--member=serviceAccount:dns-sync@${PROJECT_ID}.iam.gserviceaccount.com

#	gcloud projects add-iam-policy-binding ${PROJECT_ID} \
#		--role=roles/dns.admin \
#		--member=serviceAccount:${GSA}

iam2:
	gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    	--role=roles/dns.admin \
    	--member=principal://iam.googleapis.com/projects/${GKE_PROJECT_NUMBER}/locations/global/workloadIdentityPools/${GKE_PROJECT_ID}.svc.id.goog/subject/ns/dns-system/sa/default \

# IAM for the GKE K8S pod
iam-gke:
	gcloud projects add-iam-policy-binding projects/${PROJECT_ID} \
      --member "serviceAccount:${GKE_PROJECT_ID}.svc.id.goog[dns-system/default]" \
      --role=roles/dns.admin \


# Test project SA for cross access.
iam3:
	gcloud projects add-iam-policy-binding projects/${PROJECT_ID} \
      --member "serviceAccount:k8s-dev@costin-asm1.iam.gserviceaccount.com" \
      --role=roles/dns.admin
