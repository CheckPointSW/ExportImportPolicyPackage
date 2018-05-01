from __future__ import print_function

import argparse

from cp_mgmt_api_python_sdk.lib import APIClientArgs
from exporting.export_package import export_package
from importing.import_package import import_package
from utils import process_arguments, extract_sid_from_session_file, handle_login_fail

debug = None
log_file = None
output_file = None
client = None

from cp_mgmt_api_python_sdk.lib import APIClient

if __name__ == "__main__":

    arg_parser = argparse.ArgumentParser(description="R80.X Policy Package Export/Import Tool, V3.0")
    args = process_arguments(arg_parser)
    args_for_client = APIClientArgs(server=args.management, port=args.port,
                                    sid=args.session_id, debug_file=log_file, api_version=args.version,
                                    proxy_host=args.proxy, proxy_port=args.proxy_port, unsafe=args.unsafe,
                                    unsafe_auto_accept=args.unsafe_auto_accept)

    with APIClient(args_for_client) as client:

        if args.login == '1':
            login_reply = client.login(username=args.username, password=args.password, domain=args.domain,
                                       payload={"read-only": "true" if args.operation == "export" else "false"})
            handle_login_fail(not login_reply.success, "Login to management server failed. " + str(login_reply))
        elif args.login == '2':
            client.login_as_root(domain=args.domain)
        elif args.login == '3':
            client.sid = extract_sid_from_session_file(args.session_file)
            handle_login_fail(not client.sid, "Could not extract SID form Session-File!")
            test_reply = client.api_call("show-hosts", {"limit": 1})
            handle_login_fail(not test_reply.success, "Extract SID is invalid!")

        elif args.login == '4':
            test_reply = client.api_call("show-hosts", {"limit": 1})
            handle_login_fail(not test_reply.success, "Supplied SID is invalid!")

        if args.operation == "export":
            export_package(client, args)
        else:
            import_package(client, args)
