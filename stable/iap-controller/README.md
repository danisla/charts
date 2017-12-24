# IAP Controller for Google Kubernetes Engine

Implementation of a [LambdaController kube-metacontroller](https://github.com/GoogleCloudPlatform/kube-metacontroller) to automatically configure the [Identity Aware Proxy](https://cloud.google.com/iap/) for GCE type ingress load balancers.

This controller utilizes the following major components:
- [kube-lego](https://github.com/kubernetes/charts/tree/master/stable/kube-lego): Automatically provision SSL certificates for ingress.
- [Custom Resource Definitions (CRD)](https://kubernetes.io/docs/concepts/api-extension/custom-resources/): Used to represent the new `IapIngress` custom resource.
- [kube-metacontroller](https://github.com/GoogleCloudPlatform/kube-metacontroller): Implements the LambdaController interface for the Custom Resource Definition.
- [Extensible Service Proxy (ESP)](https://github.com/cloudendpoints/esp): Nginx based proxy used to verify the [signed IAP headers](https://cloud.google.com/iap/docs/signed-headers-howto) and proxy traffic to your Kubernetes service.

What cannot be automated at this time:
- Management of the OAuth authorized redirect URIs. This must be manually managed from the Cloud Console.

The controller performs the following actions when a new `IapIngress` resource is created:

1. Adds members from the `spec.authz` list to the `roles/iap.httpsResourceAccessor` project role.
2. Creates a new `Ingress` resource templated for the hosts specified in the `spec.services` structure.
3. Enables IAP on the load balancer backend services.
4. Creates a [Cloud Endpoints service and DNS record](https://cloud.google.com/endpoints/docs/openapi/naming-your-api-service) in the form of `SERVICE.endpoints.PROJECT_ID.cloud.goog`.
5. Deploys a wildcard OpenAPI spec to the Cloud Endpoints service configured for the IAP-enabled backend service.
6. Creates a new `Service` and `Pod` postfixed with `-esp` for the [Extensible Service Proxy](https://github.com/cloudendpoints/esp/blob/master/doc/k8s/README.md) used to verify the signed IAP headers.
  a. The backend services route traffic to the ESP service which is exposed using a `NodePort`.
  b. The ESP pod has a `readinessProbe` configured to verify that `https://HOSTNAME/_gcp_iap/identity` is responding before registering as a valid endpoint to prevent accidentally exposing your service before IAP is enabled.

## Prerequisites

1. Create GKE cluster:

```
ZONE=us-central1-b
CLUSTER_VERSION=$(gcloud beta container get-server-config --zone ${ZONE} --format='value(validMasterVersions[0])')

gcloud container clusters create dev \
  --cluster-version ${CLUSTER_VERSION} \
  --machine-type n1-standard-4 \
  --num-nodes 3 \
  --zone ${ZONE}
```

2. [Install Helm](https://github.com/kubernetes/helm/blob/master/docs/install.md#installing-the-helm-client)
3. Initialize Helm

```
kubectl create serviceaccount tiller --namespace kube-system
kubectl create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount=kube-system:tiller
helm init --service-account=tiller
```

4. Install kube-lego

```
# Production (real certs):
LEGO_URL=https://acme-v01.api.letsencrypt.org/directory

# Staging (fake certs):
LEGO_URL=https://acme-staging.api.letsencrypt.org/directory

LEGO_EMAIL=YOUR_EMAIL

helm install --name kube-lego --set config.LEGO_URL=${LEGO_URL},config.LEGO_EMAIL=${LEGO_EMAIL},rbac.create=true,rbac.serviceAccountName=kube-lego,config.LEGO_SECRET_NAME=lego-acme, stable/kube-lego
```

5. Install kube-metacontroller:

```
helm install --name metacontroller --namespace metacontroller incubator/kube-metacontroller
```

## Installing the chart

1. Create secret with your OAuth client info:
  a. Configure the [OAuth consent screen](https://console.cloud.google.com/apis/credentials/consent).
  b. Create a new [OAuth Web Application Credential](https://console.cloud.google.com/apis/credentials) and record the client ID and secret:

```
echo "CLIENT_ID=MY_CLIENT_ID" > oauth.env
echo "CLIENT_SECRET=MY_CLIENT_SECRET" >> oauth.env

kubectl create secret generic iap-oauth -n metacontroller --from-env-file=oauth.env
```

2. Create service account for the controller:

```
gcloud iam service-accounts create iap-controller \
    --display-name iap-controller

export SA_EMAIL=$(gcloud iam service-accounts list \
    --filter="displayName:iap-controller" \
    --format='value(email)')
export PROJECT=$(gcloud config get-value project)

for role in roles/editor roles/resourcemanager.projectIamAdmin; do
  gcloud projects add-iam-policy-binding \
      $PROJECT --role ${role} --member serviceAccount:$SA_EMAIL
done

gcloud iam service-accounts keys create iap-controller-sa-key.json --iam-account $SA_EMAIL

kubectl create secret generic iap-controller-sa -n metacontroller --from-file=iap-controller-sa-key.json
```

2. Install this chart:

```
helm install --name iap-controller --namespace=metacontroller --set cloudSA.secretName=iap-controller-sa,cloudSA.secretKey=iap-controller-sa-key.json,oauthSecret=iap-oauth .
```

## Usage

To use the iap-controller, create an IapIngress resouces like the example below:

```yaml
cat > iapingress.yaml <<EOF
apiVersion: ctl.isla.solutions/v1
kind: IapIngress
metadata:
  name: iap-ingress
spec:
  authz:
  - "group:group1@example.com"
  - "user:user1@example.com"
  services:
    service1.endpoints.MY_PROJECT.cloud.goog:
      service: service1
      port: 80
    service2.endpoints.MY_PROJECT.cloud.goog:
      service: service2
      port: 80
EOF

kubectl apply -f iapingress.yaml
```

1. Add authorized users to the `authz` list.
2. If you are using the provided `*.cloud.goog` DNS records, set the values of the services entries appropriately and replace `MY_PROJECT` with the project id of your Google Cloud Platform project.
  a. If you are not using not the provided `*.cloud.goog` record) then create a CNAME record that points to the `SERVICE.endpoints.MY_PROJECT.cloud.goog` record.
3. Add the upstream service and port name to the services entries for the service you want to expose.
4. Add each of your endpoints to the authorized redirect uris for your OAuth 2.0 Client ID config:

  a. Open the OAuth 2.0 Client ID config for your credential: https://console.cloud.google.com/apis/credentials
  b. Add redirect URIs for each of your hosts in the form of: `https://HOSTNAME/_gcp_gatekeeper/authenticate`
  c. NOTE: You can also run `kubectl describe iaping iap-ingress` to see the redirect uris.

Example kubectl commands:

```
  kubectl get iaping

  kubectl describe iaping iap-ingress

  kubectl delete iaping iap-ingress
```