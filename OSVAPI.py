import requests
cve = "CVE-2023-12345"
resp = requests.post("https://api.osv.dev/v1/query", json={"query": {"cve": cve}})
print(resp.json())
