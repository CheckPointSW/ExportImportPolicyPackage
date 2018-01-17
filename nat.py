# -*- coding: utf-8 -*-

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#### DATA ####
username = "xxxx"
password = "yyyy"
host = "10.xxx.xxx.xxx"
base_url = "https://%s/web_api/" % (host)
verify = False
domain = "ACME"
policy = "RABBIT-FW"
#### DATA ####

headers = {'content-type': 'application/json'}
login_data = {'user': username, 'password': password, 'read-only': 'true', 'domain': domain}


def api_call(url, json={}):
    r = requests.post(base_url + url, json=json, headers=headers, verify=verify)
    if r.status_code == 200:
        return r.json()
    else:
        raise Exception("%s: %s - %s" % (r.status_code, r.json()["code"], r.json()["message"]))


login = api_call("login", login_data)
print("Logged in")
headers["X-chkp-sid"] = login["sid"]

# show nat rulebase
data = {'package': policy, 'limit': '100'}  # , 'use-object-dictionary': 'true'  is default value, can be omitted
out = api_call("show-nat-rulebase", data)

objects = dict()
for item in out["objects-dictionary"]:
    objects[item["uid"]] = item

for rb in out["rulebase"]:
    for srb in rb["rulebase"]:
        rule_number = srb["rule-number"]
        rule_type = srb["type"]
        rule_status = srb["enabled"]
        rule_org_dst = objects.get(srb["original-destination"], srb["original-destination"])
        rule_org_dst = rule_org_dst.get("ipv4-address", rule_org_dst["name"])
        rule_org_src = objects.get(srb["original-source"], srb["original-source"])
        rule_org_src = rule_org_src.get("ipv4-address", rule_org_src["name"])
        rule_org_srv = objects.get(srb["original-service"], srb["original-service"])
        rule_org_srv = rule_org_srv.get("name")
        rule_tran_dst = objects.get(srb["translated-destination"], srb["translated-destination"])
        if rule_tran_dst["type"] == "Original":
            rule_tran_dst = rule_org_dst
        else:
            rule_tran_dst = rule_tran_dst.get("ipv4-address", rule_tran_dst["name"])
        rule_tran_src = objects.get(srb["translated-source"], srb["translated-source"])
        if rule_tran_src["type"] == "Original":
            rule_tran_src = rule_org_dst
        else:
            rule_tran_src = rule_tran_src.get("ipv4-address", rule_tran_src["name"])
        rule_tran_srv = objects.get(srb["translated-service"], srb["translated-service"])
        if rule_tran_srv["type"] == "Original":
            rule_tran_srv = rule_org_srv
        else:
            rule_tran_srv = rule_tran_srv.get("name")

        print(
            "{rulenumber}|src:{src_orig}|dst:{dst_org}|srv:{srv_org}|src_tran:{src_tran}|dst_tran:{dst_tran}|srv_tran:{srv_tran}".format(
                rulenumber=rule_number, src_orig=rule_org_src, dst_org=rule_org_dst, srv_org=rule_org_srv,
                src_tran=rule_tran_src, dst_tran=rule_tran_dst, srv_tran=rule_tran_srv))

# logout
api_call("logout")
print("Logged out")

