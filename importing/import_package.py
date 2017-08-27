import os
import time

import sys

from importing.import_objects import import_objects
from utils import debug_log, generate_import_error_report, count_global_layers


def import_package(client, args):

    if not os.path.isfile(args.file):
        debug_log("No file named " + args.file + " found!", True, True)
        sys.exit(1)

    timestamp = time.strftime("%Y_%m_%d_%H_%M")

    if not args.name:
        try:
            package = '__'.join(args.file.split('__')[2:-1])
        except (KeyError, ValueError):
            package = "Imported_Package_" + timestamp
    else:
        package = args.name

    debug_log("Checking if package already exists...")
    show_package = client.api_call("show-package", {"name": package, "details-level": "full"})
    if "code" in show_package.data and "not_found" in show_package.data["code"]:
        debug_log("Creating a Policy Package named [" + package + "]", True)
        client.api_call("add-package", {"name": package, "access": True, "threat-prevention": True})
        client.api_call("publish", wait_for_task=True)
    else:
        print("A package named " + package + " already exists. Are you sure you want to import?")
        print("1.Yes")
        print("2.No")
        choice = ""
        chosen = False
        while not chosen:
            choice = raw_input()
            if choice not in ["1", "2"]:
                print("Please enter either '1' or '2'")
            else:
                chosen = True
        if choice == '2':
            exit(0)

    debug_log("Importing general objects", True)
    layers_to_attach = import_objects(args.file, client, {})

    num_global_access, num_global_threat = count_global_layers(client, package)

    access_layer_position = num_global_access + 1
    threat_layer_position = num_global_threat + 2

    access_layers = []
    threat_layers = []

    for access_layer in layers_to_attach["access"]:
        access_layers.append({"name": access_layer, "position": access_layer_position})
        access_layer_position += 1

    for threat_layer in layers_to_attach["threat"]:
        threat_layers.append({"name": threat_layer, "position": threat_layer_position})
        threat_layer_position += 1

    set_package_payload = {"name": package, "access-layers": {"add": access_layers},
                           "threat-layers": {"add": threat_layers}}

    debug_log("Attaching layers to package")
    layer_attachment_reply = client.api_call("set-package", set_package_payload)
    if not layer_attachment_reply.success:
        debug_log("Failed to attach layers to package! "
                  "Error: " + layer_attachment_reply.error_message + ". Import operation aborted.", True, True)
    publish_reply = client.api_call("publish", wait_for_task=True)
    if not publish_reply.success:
        debug_log("Failed to attach layers to package! "
                  "Error: " + publish_reply.error_message + ". Import operation aborted.", True, True)
        sys.exit(1)

    generate_import_error_report()


















