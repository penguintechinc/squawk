#!/usr/bin/env python3
# NOTE - this script is not complete and is meant to be used as a reference
import os
import requests
from kubernetes import client, config, watch


class DoHDNSClient:
    def __init__(self, doh_url, token):
        self.doh_url = doh_url
        self.token = token

    def resolve(self, name):
        headers = {
            "Content-Type": "application/dns-message",
            "Authorization": f"Bearer {self.token}",
        }
        params = {"name": name, "type": "A"}
        response = requests.get(self.doh_url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()


def main():
    config.load_incluster_config()
    v1 = client.CoreV1Api()
    w = watch.Watch()

    doh_url = os.getenv("DOH_URL", "https://dns.google/dns-query")
    token = os.getenv("DNS_TOKEN", "")

    dns_client = DoHDNSClient(doh_url, token)

    for event in w.stream(v1.list_namespaced_pod, namespace="default"):
        pod = event["object"]
        pod_name = pod.metadata.name
        try:
            dns_response = dns_client.resolve(pod_name)
            print(f"Resolved {pod_name}: {dns_response}")
        except requests.RequestException as e:
            print(f"Failed to resolve {pod_name}: {e}")


if __name__ == "__main__":
    main()
