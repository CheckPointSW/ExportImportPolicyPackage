from __future__ import print_function

import sys

import argparse

from cpapi import APIClient, APIClientArgs
from exporting.export_package import export_package
from importing.import_package import import_package
from utils import process_arguments, extract_sid_from_session_file, handle_login_fail, get_min_version, debug_log

debug = None
log_file = None
output_file = None
client = None


def get_version(client):
    if not client.api_version:
        res = client.api_call("show-api-versions")
        handle_login_fail(not res.success, "couldn't get api version")
        client.api_version = res.data["current-version"]


if __name__ == "__main__":
    if sys.version_info < (3, 7):
        raise Exception("Min Python version required is 3.7")

    arg_parser = argparse.ArgumentParser(description="R80.X Policy Package Export/Import Tool, V6.2.0")
    args = process_arguments(arg_parser)
    if args.force:
        args.unsafe_auto_accept = True
    args_for_client = APIClientArgs(server=args.management, port=args.port,
                                    sid=args.session_id, debug_file=log_file,
                                    proxy_host=args.proxy, proxy_port=args.proxy_port, unsafe=args.unsafe,
                                    unsafe_auto_accept=args.unsafe_auto_accept, cloud_mgmt_id=args.cloud_mgmt_id)

    with APIClient(args_for_client) as client:
        payload = {}
        if args.login == '1':
            payload["read-only"] = "true" if args.operation == "export" else "false"
            if args.session_timeout:
                payload["session-timeout"] = args.session_timeout
            if args.api_key:
                login_reply = client.login_with_api_key(api_key=args.api_key, domain=args.domain,
                                                        payload=payload)
            else:
                login_reply = client.login(username=args.username, password=args.password, domain=args.domain,
                                           payload=payload)
            handle_login_fail(not login_reply.success, "Login to management server failed. " + str(login_reply))
        elif args.login == '2':
            if args.session_timeout:
                payload["session-timeout"] = args.session_timeout
            client.login_as_root(domain=args.domain, payload=payload)
        elif args.login == '3':
            args.session_file = input("Please enter path to session file: ")
            client.sid = extract_sid_from_session_file(args.session_file)
            handle_login_fail(not client.sid, "Could not extract SID form Session-File!")
            test_reply = client.api_call("show-hosts", {"limit": 1})
            handle_login_fail(not test_reply.success, "Extract SID is invalid!")
            get_version(client)
        elif args.login == '4':
            if args.session_id:
                client.sid = args.session_id
            else:
                client.sid = input("Please enter sid: ")
            test_reply = client.api_call("show-hosts", {"limit": 1})
            handle_login_fail(not test_reply.success, "Supplied SID is invalid!")
            get_version(client)
        if args.version:
            min_version = get_min_version(client.api_version, args.version)
            debug_log("Machine API version: " + client.api_version + ", given API version: " + args.version +
                      ", setting API version to: " + min_version, True, True)
            client.api_version = min_version
        if args.operation == "export":
            export_package(client, args)
        else:
            import_package(client, args)
