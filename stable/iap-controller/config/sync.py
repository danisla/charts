#!/usr/bin/env python
from __future__ import print_function
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from oauth2client.service_account import ServiceAccountCredentials
from httplib2 import Http
import base64
import copy
import googleapiclient.discovery
import hashlib
import json
import os
import re
import requests
import sys
import time
import yaml

TEMPLATE_PATH = os.environ.get("TEMPLATE_PATH", "/hooks")
OAUTH_CLIENT_ID_PATH = "/var/run/secrets/oauth/CLIENT_ID"
OAUTH_CLIENT_SECRET_PATH = "/var/run/secrets/oauth/CLIENT_SECRET"
ESP_IMAGE = os.environ.get("ESP_IMAGE", "gcr.io/endpoints-release/endpoints-runtime:1")
SA_KEY = os.environ.get("SA_KEY", "/var/run/secrets/sa/sa_key.json")

def get_auth(sa_key):
  scopes = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/service.management",
    "https://www.googleapis.com/auth/compute"
  ]

  credentials = ServiceAccountCredentials.from_json_keyfile_name(sa_key, scopes=scopes)

  http_auth = credentials.authorize(Http())

  return http_auth

def load_template(name):
  with open(os.path.join(TEMPLATE_PATH, name)) as f:
    return f.read()

def new_svc(parent, namespace, name, host):
  esp_svc_template = yaml_to_json(load_template("esp-svc.yaml"))
  return json.loads(esp_svc_template.replace("${NAMESPACE}", namespace).replace("${SERVICE}", name).replace("${HOST}", host))

def new_ing(parent, children, namespace, name):
  ing = None
  ing_template = yaml_to_json(load_template("ingress.yaml")).replace("${NAMESPACE}", namespace)
  ing = json.loads(ing_template)
  ing["spec"] = {}

  services = sorted(children["Service.v1"].keys())

  rules = []
  hosts = []
  for svc in services:
    host = children["Service.v1"][svc]["metadata"]["annotations"]["iapingresses.ctl.isla.solutions/host"]
    hosts.append(host)

    rule = {
      "host": host,
      "http": {
        "paths": [{
          "path": "/*",
          "backend": {
            "serviceName": svc,
            "servicePort": 80
          }
        }]
      }
    }
    rules.append(rule)

  ing["spec"]["rules"] = rules
  ing["spec"]["tls"] = [{
    "secretName": "iap-ingress-tls",
    "hosts": hosts
  }]

  return ing

def get_ingress_ip(children):
  ing = children["Ingress.extensions/v1beta1"].get("iap-ingress", None)
  if not ing:
    return None
  
  return ing.get("status", {}).get("loadBalancer", {}).get("ingress", [{}])[0].get("ip", None)

metadata_cache = {}
def get_metadata(path, cache=True):
  if cache and metadata_cache.get(path, None):
    return metadata_cache[path]

  METADATA_URL = 'http://metadata.google.internal/computeMetadata/v1/'
  METADATA_HEADERS = {'Metadata-Flavor': 'Google'}
  url = METADATA_URL + path
  r = requests.get(url,headers=METADATA_HEADERS)
  if r.status_code == 200:
    if cache:
      metadata_cache[path] = str(r.text)
    return str(r.text)
  else:
    return None

def get_project():
  return get_metadata('project/project-id')

def get_project_num():
  return get_metadata('project/numeric-project-id')

def get_backends(project, children):
  compute = googleapiclient.discovery.build('compute', 'v1', http=get_auth(SA_KEY))
  backends = compute.backendServices().list(project=project).execute().get("items", [])
  filtered = {}
  # Extract node ports for services.
  for svc_name, svc in children["Service.v1"].items():
    for b in backends:
      if b["name"].split("-")[2] == str(svc["spec"]["ports"][0]["nodePort"]):
        filtered[svc_name] = {
          "name": str(b["name"]),
          "id": str(b["id"]),
          "iap": b.get("iap", None)
        }
  return filtered

def enable_iap(project, backend, oauth_client_id, oauth_secret):
  compute = googleapiclient.discovery.build('compute', 'v1', http=get_auth(SA_KEY))
  oauth_secret_sha256 = hashlib.sha256(oauth_secret).hexdigest()
  body = {
    "iap": {
      "enabled": True,
      "oauth2ClientId": oauth_client_id,
      "oauth2ClientSecret": oauth_secret,
      "oauth2ClientSecretSha256": oauth_secret_sha256
    }
  }
  return compute.backendServices().patch(project=project, backendService=backend, body=body).execute()

def add_iam_policy(project, members, role):
  resourcemanager = googleapiclient.discovery.build('cloudresourcemanager', 'v1', http=get_auth(SA_KEY))
  curr_iam_policy = resourcemanager.projects().getIamPolicy(resource=project, body={}).execute()
  policy = {"bindings": [], "version": 1}
  curr_binding = None
  for binding in curr_iam_policy["bindings"]:
    if binding["role"] == role:
      curr_binding = binding
    else:
      policy["bindings"].append(binding)
  if curr_binding:
    new_members = list(set(curr_binding["members"] + members)) 
  else:
    new_members = members

  policy["bindings"].append({
    "members": new_members,
    "role": role
  })

  return resourcemanager.projects().setIamPolicy(resource=project, body={"policy": policy}).execute()

def new_openapi_sig(parent, backend, endpoint_url, project_num, ingress_ip):
  jwt_aud = "/projects/%s/global/backendServices/%s" % (project_num, backend["id"])
  uid = parent["metadata"]["uid"]
  sig = hashlib.sha224("|".join([endpoint_url, jwt_aud, ingress_ip, uid])).hexdigest()
  return sig

def new_openapi(parent, backend, endpoint_url, project_num, ingress_ip, sig):
  openapi_template = load_template("openapi.yaml")

  jwt_aud = "/projects/%s/global/backendServices/%s" % (project_num, backend["id"])
  rendered = openapi_template.replace("${JWT_AUDIENCE}", jwt_aud).replace("${ENDPOINT_URL}", endpoint_url).replace("${INGRESS_IP}", ingress_ip).replace("${SIG}", sig)
  return rendered

def get_endpoint_configs(project, endpoint_url):
  servicemanagement = googleapiclient.discovery.build('servicemanagement', 'v1', http=get_auth(SA_KEY))
  return servicemanagement.services().configs().list(serviceName=endpoint_url).execute()

def list_endpoint_services(project, pageSize=2000):
  servicemanagement = googleapiclient.discovery.build('servicemanagement', 'v1', http=get_auth(SA_KEY))
  return servicemanagement.services().list(producerProjectId=project, pageSize=pageSize).execute()

def create_endpoint_service(project, endpoint_url):
  servicemanagement = googleapiclient.discovery.build('servicemanagement', 'v1', http=get_auth(SA_KEY))
  return servicemanagement.services().create(body={"producerProjectId": project, "serviceName": endpoint_url}).execute()

def get_endpoint_rollouts(endpoint_url, pageSize=2000):
  servicemanagement = googleapiclient.discovery.build('servicemanagement', 'v1', http=get_auth(SA_KEY))
  return servicemanagement.services().rollouts().list(serviceName=endpoint_url, pageSize=pageSize).execute()

def submit_endpoint_api(endpoint_url, spec):
  servicemanagement = googleapiclient.discovery.build('servicemanagement', 'v1', http=get_auth(SA_KEY))
  b64spec = base64.b64encode(spec)
  body = {
    "validateOnly": False,
    "configSource": {
      "files": [{
        "fileContents": b64spec,
        "filePath": "openapi.yaml",
        "fileType": "OPEN_API_YAML"
      }]
    }
  }
  return servicemanagement.services().configs().submit(serviceName=endpoint_url, body=body).execute()

def rollout_endpoint_config(endpoint_url, config_version):
  servicemanagement = googleapiclient.discovery.build('servicemanagement', 'v1', http=get_auth(SA_KEY))
  body = {"trafficPercentStrategy": {"percentages": {}}}
  body["trafficPercentStrategy"]["percentages"][config_version] = 100.0
  return servicemanagement.services().rollouts().create(serviceName=endpoint_url, body=body).execute()

def new_esp_pod(namespace, svc_name, svc_port, endpoint_url, host, config_version):
  pod_template = load_template("esp-pod.yaml")
  upstream = "%s:%s" % (svc_name, svc_port)
  rendered = pod_template.replace("${IMAGE}", ESP_IMAGE).replace("${NAMESPACE}", namespace).replace("${UPSTREAM}", upstream).replace("${SERVICE}", svc_name).replace("${ENDPOINT_URL}", endpoint_url).replace("${HOST}", host).replace("${ENDPOINT_VERSION}", config_version)
  return json.loads(yaml_to_json(rendered))

def new_endpoint_url(service, project):
  return "%s.endpoints.%s.cloud.goog" % (service, project)

def new_svc_status(host, svc_name):
   return {
      "endpoint": "PENDING",
      "redirectUri": "https://%s/_gcp_gatekeeper/authenticate" % host,
      "backend": "UNKNOWN",
      "config": "UNKNOWN",
      "iap": "UNKNOWN",
      "upstreamService": svc_name,
      "espPod": "UNKNOWN"
    }

def get_svc_status(parent):
  return parent.get("status", {}).get("services", {k:new_svc_status(k,v["service"]) for k,v in parent["spec"]["services"].items()})

class Controller(BaseHTTPRequestHandler):
  def log_message(self, format, *args):
    eprint("%s - - [%s] %s" %
            (self.address_string(),
            self.log_date_time_string(),
            format%args))

  def sync(self, parent, children):
    desired_status = {}
    desired_children = []
    svc_status = get_svc_status(parent)

    project = get_project()
    assert project is not None, "error getting project id from metadata server"
    project_num = get_project_num()
    assert project_num is not None, "error getting project number from metadataa server"

    # Sync the IAM role
    iam_status = parent.get("status", {}).get("authorization", "PENDING")
    if iam_status == "PENDING":
      members = parent["spec"].get("authz", [])
      res = add_iam_policy(project, members, "roles/iap.httpsResourceAccessor")
      desired_status["authorization"] = "%d members" % len(members)
    elif iam_status != "PENDING":
      desired_status["authorization"] = iam_status

    # Sync the Kubernetes Ingress object
    ing_name = "iap-ingress"
    ing_namespace = parent["spec"].get("ingressNamespace", "default")
    ing = children["Ingress.extensions/v1beta1"].get(ing_name, new_ing(parent, children, ing_namespace, ing_name))
    if ing is not None:
      desired_children.append(ing)

    # Sync Kubernetes service for each host
    for host, svc_spec in parent["spec"]["services"].items():
      svc_name = svc_spec["service"]
      namespace = svc_spec.get("namespace", "default")
      svc = children["Service.v1"].get("%s-esp" % svc_name, new_svc(parent, namespace, svc_name, host))
      desired_children.append(svc)
    
    # Sync the Kubernetes ESP pod for each host
    for host, svc_spec in parent["spec"]["services"].items():
      svc_name = svc_spec["service"]
      svc_port = svc_spec["port"]
      namespace = svc_spec.get("namespace", "default")
      config_version = svc_status[host]["config"]
      endpoint_url = new_endpoint_url(svc_name, project)

      pod = children["Pod.v1"].get("%s-esp" % svc_name, new_esp_pod(namespace, svc_name, svc_port, endpoint_url, host, config_version))

      if svc_status[host]["espPod"] == "UNKNOWN" and config_version not in ["UNKNOWN","CREATING","PENDING"]:
        # Verify rollout is complete:
        rollouts = get_endpoint_rollouts(endpoint_url).get("rollouts", [])
        found = False
        for rollout in rollouts:
          if rollout.get("trafficPercentStrategy", {}).get("percentages", {}).get(config_version) == 100.0:
            found = True
            if rollout["status"] == "SUCCESS":
              self.log_message("Creating ESP pod for: endpoint=%s, config=%s", endpoint_url, config_version)
              svc_status[host]["espPod"] = "PENDING"
              desired_children.append(pod)
            elif rollout["status"] in ["FAILED", "CANCELLED"]:
              self.log_message("ESP config rollout failed: endpoibnt=%s, reason=%s", endpoint_url, rollout["status"])
              svc_status[host]["espPod"] = "FAILED"
            else:
              self.log_message("Waiting for ESP config rollout to complete: status=%s, endpoint=%s, config=%s", rollout["status"], endpoint_url, config_version)
        if not found:
          self.log_message("WARN: Endpoint service rollout for config %s not found", config_version)
            
      elif svc_status[host]["espPod"] == "PENDING":
        self.log_message("Waiting for ESP pod to become ready for: endpoint=%s, config=%s", endpoint_url, config_version)
        desired_children.append(pod)
        for condition in pod.get("status", {}).get("conditions", []):
          if condition["type"] == "Ready" and condition["status"] == "True":
            svc_status[host]["espPod"] = "READY"
            break
      else:
        if svc_status[host]["espPod"] == "READY":
          desired_children.append(pod)
    
    # Sync openapi spec for cloud endpoints creation.
    ingress_ip = get_ingress_ip(children)
    if ingress_ip:
      for host, svc_spec in sorted(parent["spec"]["services"].items()):
        svc_name = svc_spec["service"]
        
        # Sync IAP
        if svc_status[host]["iap"] == "UNKNOWN":

          backends = get_backends(project, children)
          backend = backends[svc_name + "-esp"]

          self.log_message("Enabling IAP on backend service: %s", backend["name"])

          client_id = open(OAUTH_CLIENT_ID_PATH,"r").read()
          client_secret = open(OAUTH_CLIENT_SECRET_PATH,"r").read()
          
          iap_status = enable_iap(project, backend["name"], client_id, client_secret)

          if iap_status["status"] == "PENDING":
            svc_status[host]["iap"] = "PENDING"
          else:
            iap_status["status"] = "ERROR"

        elif svc_status[host]["iap"] == "PENDING":
          
          backends = get_backends(project, children)
          backend = backends[svc_name + "-esp"]

          if backend["iap"] and backend["iap"]["enabled"]:
            self.log_message("IAP enabled on backend service: %s", backend["name"])
            svc_status[host]["iap"] = "Enabled"

        config = svc_status[host]["config"]
        endpoint_url = new_endpoint_url(svc_name, project)
        
        if config == "UNKNOWN":
          
          availableServices = [i["serviceName"] for i in list_endpoint_services(project)["services"]]
          if endpoint_url not in availableServices:
            self.log_message("Creating Endpoint service for: %s", endpoint_url)
            res = create_endpoint_service(project, endpoint_url)

          svc_status[host]["endpoint"] = endpoint_url
          svc_status[host]["config"] = "CREATING"
        
        elif config == "CREATING":
          availableServices = [i["serviceName"] for i in list_endpoint_services(project)["services"]]
          if endpoint_url in availableServices:
            backends = get_backends(project, children)
            backend = backends[svc_name + "-esp"]
            sig = new_openapi_sig(parent, backend, endpoint_url, project_num, ingress_ip)

            self.log_message("Generating openapi spec with svc_name=%s, backend=%s, endpoint_url=%s, project_num=%s, ingress_ip=%s", svc_name, backend, endpoint_url, project_num, ingress_ip)
            service_openapi_yaml = new_openapi(parent, backend, endpoint_url, project_num, ingress_ip, sig)
            
            self.log_message("Deploying Cloud Endpoints service: %s", endpoint_url)

            res = submit_endpoint_api(endpoint_url, service_openapi_yaml)

            svc_status[host]["backend"] = backend["name"]
            svc_status[host]["config"] = "PENDING"
          else:
            self.log_message("Waiting for Endpoint service creation: %s", endpoint_url)

        elif config == "PENDING":
          # Find config with matching signature.
          backends = get_backends(project, children)
          backend = backends[svc_name + "-esp"]
          sig = new_openapi_sig(parent, backend, endpoint_url, project_num, ingress_ip)

          self.log_message("Waiting for Cloud Endpoints service submission: %s. sig=%s", endpoint_url, sig)
          svc_status[host]["config"] = "PENDING"

          configs = get_endpoint_configs(project, endpoint_url)

          epcfg = None
          for c in configs.get("serviceConfigs", []):
            pattern = "SIG=%s" % sig
            if pattern in c["documentation"]["summary"]:
              epcfg = c
              break

          if epcfg:
            self.log_message("Cloud Endpoints service submission complete: %s. config=%s", endpoint_url, epcfg["id"])

            #TODO: check to see if rollout is even needed by verifying signature in latest rollout.
            res = rollout_endpoint_config(endpoint_url, epcfg["id"])
            #TODO: save the res["rolloutId"] to status field and use to wait on rollout.
            svc_status[host]["config"] = epcfg["id"]

          else:
            svc_status[host]["config"] = "PENDING"
    else:
      self.log_message("Waiting for ingress IP address to create Cloud Endpoints services")

    desired_status["services"] = svc_status
    desired_status["address"] = ingress_ip or "PENDING"
    desired_status["numHosts"] = len(parent["spec"]["services"].keys())

    return {'status': desired_status, 'children': desired_children}
  
  def do_GET(self):
    if "/healthz" in self.path:
      self.send_response(200)
      self.send_header('Content-type', 'text/plain')
      self.end_headers()
      self.wfile.write("OK")

  def do_POST(self):
    observed = json.loads(self.rfile.read(int(self.headers.getheader('content-length'))))
    desired = self.sync(observed['parent'], observed['children'])    

    self.log_message("Completed sync of %d hosts", desired["status"]["numHosts"])

    self.send_response(200)
    self.send_header('Content-type', 'application/json')
    self.end_headers()
    self.wfile.write(json.dumps(desired))

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def yaml_to_json(src):
  return json.dumps(yaml.load(src), sort_keys=True, indent=2)

eprint("LambdaController listening on port 80")
HTTPServer(('', 80), Controller).serve_forever()