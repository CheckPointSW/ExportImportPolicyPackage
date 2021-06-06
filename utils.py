from __future__ import print_function

import copy
import csv
import imp
import json
import os
import re
import sys
import tarfile

from lists_and_dictionaries import singular_to_plural_dictionary, fields_to_change, \
    fields_to_exclude_in_the_presence_of_other_fields, fields_to_exclude_from_import_by_api_type_and_versions, \
    partially_exportable_types, unexportable_objects_map
from menu import Menu


def populate_parser(parser):
    parser.add_argument("-op", "--operation", required=False, help="Operation type: Import or Export",
                        choices=["import", "export"])
    parser.add_argument("-n", "--name", required=False, help="The name of the policy package to export or import")
    parser.add_argument("-f", "--file", required=False, help="The path to the tar file containing the data to import")
    parser.add_argument("--all", required=False,
                        help="Indicates whether to export or import all types of layers", action="store_true")
    parser.add_argument("-ac", "--access", required=False, default=True,
                        help="Indicates whether to export or import the Access-Control layers", action="store_true")
    parser.add_argument("-tp", "--threat", required=False,
                        help="Indicates whether to export or import the Threat-Prevention layers", action="store_true")
    parser.add_argument("--nat", required=False, action="store_true",
                        help="Indicates whether to export or import the NAT rules")
    parser.add_argument("--https", required=False,
                        help="Indicates whether to export or import the HTTPS Inspection layers", action="store_true")
    parser.add_argument("-o", "--output-file", required=False, help="The name of output file")
    parser.add_argument("-u", "--username", required=False, default=os.getenv('MGMT_CLI_USER'),
                        help="The management administrator's user name.\nEnvironment variable: MGMT_CLI_USER")
    parser.add_argument("-p", "--password", required=False,
                        help="The management administrator's password.\nEnvironment variable: MGMT_CLI_PASSWORD")
    parser.add_argument("-m", "--management", required=False, default=os.getenv('MGMT_CLI_MANAGEMENT', "127.0.0.1"),
                        help="The management server's IP address (In the case of a Multi-Domain Environment, use the IP address of the MDS domain).\nDefault: 127.0.0.1\nEnvironment variable: MGMT_CLI_MANAGEMENT")
    parser.add_argument("--port", "--server-port", required=False, default=os.getenv('MGMT_CLI_PORT', 443),
                        help="The port of the management server\nDefault: 443\nEnvironment variable: MGMT_CLI_PORT")
    parser.add_argument("--proxy", required=False, help="The proxy server")
    parser.add_argument("--proxy-port", required=False, help="The port of the proxy server")
    parser.add_argument("-d", "--domain", required=False, default=os.getenv('MGMT_CLI_DOMAIN'),
                        help="The name, uid or IP-address of the management domain\nEnvironment variable: MGMT_CLI_DOMAIN")
    parser.add_argument("-s", "--session-file", required=False, default=os.getenv('MGMT_CLI_SESSION_FILE'),
                        help="A file containing the session information retrieved by a previous login operation.\nEnvironment variable: MGMT_CLI_SESSION_FILE")
    parser.add_argument("-sid", "--session-id", required=False, default=os.getenv('MGMT_CLI_SESSION_ID'),
                        help="The session identifier (sid) acquired from a previous login operation\nEnvironment variable: MGMT_CLI_SESSION_ID")
    parser.add_argument("-r", "--root", required=False,
                        action="store_true",
                        help="When running on a management server, use this flag to login with root privileges")
    parser.add_argument("-v", "--version", required=False,
                        default=None,
                        help="Forces the tool to use the supplied Web API version")
    parser.add_argument("--non-user-created", required=False, default="false", choices=["true", "false"],
                        help="Indicates whether to show only user created data.\nDefault: true")
    parser.add_argument("--debug", required=False, default=os.getenv('MGMT_CLI_DEBUG', 'off'),
                        choices=["on", "off"],
                        help="Indicates whether to run the script in debug mode.\nDefault: off\nEnvironment variable: MGMT_CLI_DEBUG")
    parser.add_argument("--log-file", required=False,
                        default="import_export.log",
                        # os.getenv('MGMT_CLI_LOG_FILE', "get_objects.log"),
                        help="The path to the debugging log file\nDefault: get_objects.log\nEnvironment variable: MGMT_CLI_LOG_FILE")
    parser.add_argument("--objects-suffix", required=False, default="",
                        help="Add suffix to user defined object names.")
    parser.add_argument("--unsafe", required=False, action="store_true",
                        help="UNSAFE! Ignore certificate verification.")
    parser.add_argument("--unsafe-auto-accept", required=False, action="store_true",
                        help="UNSAFE! Auto accept fingerprint during certificate verification.")
    parser.add_argument("-t", "--session-timeout", required=False,
                        help="Session expiration timeout in seconds.")
    parser.add_argument("--force", required=False, default=False, action="store_true",
                        help="Force run the command with no confirmation. WARNING! - this will set unsafe-auto-accept to be true as well.")
    parser.add_argument("--strict", required=False, default=False, action="store_true",
                        help="Stop import on first API error.")
    return parser.parse_args()


attribute_export_error_num = 1


def process_arguments(parser):
    args = populate_parser(parser)
    args = Menu(args).self_args
    global debug
    global err_msgs
    global log_file

    debug = args.debug
    err_msgs = []

    if args.debug and args.log_file:
        try:
            log_file = open(args.log_file, "wb")
        except IOError as e:
            debug_log("Could not open given log file [" + args.log_file + "] for writing : " + str(e) + ". "
                                                                                                        "Sending debug information to stdout.",
                      True)
    else:
        log_file = None

    return args


def debug_log(string, print_to_stdout=False, print_to_error_log=False):
    if debug:
        string += '\n'
        # If we have a log file set by a program argument flag
        if log_file:
            print_safe(string, log_file)
        elif not print_to_stdout:
            print_safe(string, sys.stdout)

    if print_to_stdout:
        print_safe(string, sys.stdout)
    if print_to_error_log:
        err_msgs.append(string + "\n\n")


def print_safe(string, file_to_write):
    try:
        print(string, file=file_to_write)
    except UnicodeEncodeError:
        print(string.encode('utf-8'), file=file_to_write)


# Helper function. Compares two strings of version numbers -> "1.2.1" > "1.1", "0.9.0" == "0.9"
#
# Arguments:
#    version1
#    version2
# Return:
#  1 -> version1 >  version2
#  0 -> version1 == version2
# -1 -> version1 <  version2
def compare_versions(version1, version2):
    v1_nums = version1.split('.')
    v2_nums = version2.split('.')
    min_length = min(len(v1_nums), len(v2_nums))
    i = 0
    while i < min_length:
        if v1_nums[i] < v2_nums[i]:
            return -1
        elif v1_nums[i] > v2_nums[i]:
            return 1
        i += 1
    return -1 if (len(v1_nums) < len(v2_nums)) else 1 if (len(v1_nums) > len(v2_nums)) else 0


def get_special_treatment_list():
    _, pathname, description = imp.find_module("exporting.special_treatment_objects")
    return set([os.path.splitext(module)[0]
                for module in os.listdir(pathname)
                if module.endswith('.py')])


def extract_sid_from_session_file(session_file):
    with open(session_file) as f:
        content = f.readlines()
    for line in content:
        if "sid" in line:
            return line.split(" ")[1].split("\"")[1]
    return None


def handle_login_fail(test_fail, message):
    if test_fail:
        debug_log(message, True, True)
        sys.exit(1)


# Validates the fingerprint of the server with a local one
# If it's validated, assign the API client's fingerprint accordingly
# If not, display an error and exit.
def validate_fingerprint_without_prompt(client, server, auto_accept=False, local_fingerprint=None):
    # If given a fingerprint, save it so we don't have to give it next time
    if local_fingerprint:
        client.save_fingerprint_to_file(server, local_fingerprint)
    # If not given a fingerprint, try to read one from a file previously written
    else:
        local_fingerprint = client.read_fingerprint_from_file(server)
    # Getting the server's fingerprint
    server_fingerprint = client.get_server_fingerprint(server)
    if local_fingerprint.replace(':', '').upper() == server_fingerprint.replace(':', '').upper():
        client.fingerprint = local_fingerprint
        client.save_fingerprint_to_file(server, client.fingerprint)
        return True
    elif auto_accept:
        debug_log("Accepting the fingerprint " + server_fingerprint +
                  ".\n Please note that this is unsafe and you may be a victim to a Man-in-the-middle attack.",
                  True)
        client.fingerprint = server_fingerprint
        client.save_fingerprint_to_file(server, client.fingerprint)
        return True
    else:
        debug_log("Cannot operate on an unverified server. Please verify the server's fingerprint: '"
                  + server_fingerprint + "' and add it via the 'fingerprint' option of this module.", True, True)
        return False


def get_range(lst, begin, end):
    return lst[begin:end + 1]


def find_min_position_group(exception_groups):
    min_group = min(exception_groups, key=lambda x: max(x['positions']))
    exception_groups.remove(min_group)
    return min_group


def create_tar_file(layer_data, data_dict, timestamp, lst, api_version):
    layer_type = layer_data["type"].split("-")[0]
    layer_tar_name = "exported__" + layer_type + "_layer__" + layer_data["name"] + "__" + timestamp + ".tar.gz"
    # TODO AdamG What about with and IOException
    with tarfile.open(layer_tar_name, "w:gz") as tar:
        export_to_tar(data_dict, timestamp, tar, lst, api_version)
    return layer_tar_name


def export_to_tar(data_dict, timestamp, tar, lst, api_version, ignore_list=None):
    counter = 1
    for api_type in lst:
        if ignore_list and [x for x in ignore_list if x in api_type]:
            continue
        if data_dict.get(api_type):
            if singular_to_plural_dictionary[api_version][api_type] == "generic-object":
                file_command = "add-generic-object-" + api_type
            else:
                file_command = "add-" + api_type
            file_name_csv = str(counter).zfill(2) + "__" + "__" + file_command + "__" + timestamp + ".csv"
            file_name_json = str(counter).zfill(2) + "__" + "__" + file_command + "__" + timestamp + ".json"
            with open(file_name_csv, "wb") as tar_file_csv, open(file_name_json, "wb") as tar_file_json:
                write_data(data_dict[api_type], tar_file_csv, ".csv")
                write_data(data_dict[api_type], tar_file_json, ".json")
            tar.add(file_name_csv)
            tar.add(file_name_json)
            try:
                os.remove(file_name_csv)
                os.remove(file_name_json)
            except WindowsError as err:
                print(err, file=sys.stderr)

        counter += 1

    file_name_version = "version.txt"
    with open(file_name_version, "wb") as tar_file_version:
        tar_file_version.write(api_version)
    tar.add(file_name_version)
    try:
        os.remove(file_name_version)
    except WindowsError as err:
        print(err, file=sys.stderr)


def write_data(json_data, out_file, file_format, close_file=True):
    for obj in json_data:
        for field in obj:
            if obj[field] in unexportable_objects_map:
                obj[field] = unexportable_objects_map[obj[field]]
    if "json" in file_format:
        json.dump(json_data, out_file, indent=4)
    else:
        res = flat_json_to_csv(json_data)
        writer = csv.writer(out_file)
        writer.writerows(res)
    if close_file and (out_file is not None and out_file is not sys.stdout):
        out_file.close()


def flat_json_to_csv(json_data):
    global attribute_export_error_num

    # We use a special_keys container for access rule's source, destination and service fields.
    # We want to sort these keys natural way!!!
    keys = []
    special_keys = []

    for item in json_data:
        for key in item:
            sKey = str(key)
            if sKey.startswith('source.', 0) or sKey.startswith('destination.', 0) or sKey.startswith('service.', 0):
                if key not in special_keys:
                    special_keys.append(key)
            elif key not in keys:
                keys.append(key)

    keys.sort()
    special_keys.sort(natural_sort_cmp)

    keys.extend(special_keys)
    res = [keys]

    for item in json_data:
        lst = []
        for key in keys:
            attribute = item[key] if key in item and item[key] is not None else ""
            if isinstance(attribute, bool):
                if attribute:
                    string = "true"
                else:
                    string = "false"
            elif isinstance(attribute, int) or isinstance(attribute, long):
                string = str(attribute)
            else:
                try:
                    string = attribute.encode('utf-8').replace('\\\\', '\\')
                except UnicodeEncodeError:
                    string = "ATTRIBUTE_EXPORT_ERROR_" + attribute_export_error_num
                    attribute_export_error_num += 1
            lst.append(string)
        res.append(lst)

    return res


def natural_sort_key(astr):
    return [int(s) if s.isdigit() else s for s in re.split(r'(\d+)', astr)]


def natural_sort_cmp(s1, s2):
    return cmp(natural_sort_key(s1), natural_sort_key(s2))


def flatten_json(json_node):
    flat_json = {}
    if isinstance(json_node, dict):
        for key in json_node.keys():
            if key in fields_to_exclude_in_the_presence_of_other_fields and \
                            fields_to_exclude_in_the_presence_of_other_fields[key] in json_node.keys():
                continue
            if key in fields_to_change:
                json_node[fields_to_change[key]] = json_node[key]
                json_node.pop(key)
                flat_json = merge_flat_data(json_node, flat_json, fields_to_change[key])
            else:
                flat_json = merge_flat_data(json_node, flat_json, key)
    elif isinstance(json_node, list):
        for i in range(len(json_node)):
            flat_json = merge_flat_data(json_node, flat_json, i)
    else:
        flat_json = json_node
    return flat_json


def merge_flat_data(json_node, flat_json, key):
    flat_json_of_key = flatten_json(json_node[key])
    if not isinstance(flat_json_of_key, dict):
        flat_json[key] = flat_json_of_key
    else:
        for sub_key in flat_json_of_key:
            flat_json[str(key) + "." + str(sub_key)] = flat_json_of_key[sub_key]
    return flat_json


def merge_data(destination, source):
    if isinstance(source, list):
        if isinstance(destination, list):
            for data in source:
                if data not in destination:
                    destination.append(data)
        elif isinstance(destination, dict):
            for data in source:
                if data["type"] not in destination:
                    destination[data["type"]] = []
                if data not in destination[data["type"]]:
                    destination[data["type"]].append(data)
    elif isinstance(source, dict):
        if isinstance(destination, list):
            for key in source.keys():
                for data in source[key]:
                    if data not in destination:
                        destination.append(data)
        elif isinstance(destination, dict):
            for key in source.keys():
                if key not in destination:
                    destination[key] = []
                for data in source[key]:
                    if data not in destination[key]:
                        destination[key].append(data)
    return destination


def split_list_items(item_list):
    item_groups = []
    multi_value_index = item_list[0].split(".")[0]
    sub_list = []
    for item in item_list:
        if item.split(".")[0] != multi_value_index:
            item_groups.append(copy.deepcopy(sub_list))
            sub_list = []
            multi_value_index = item.split(".")[0]
        sub_list.append(".".join(item.split(".")[1:]))
    item_groups.append(copy.deepcopy(sub_list))
    return item_groups


def create_payload(fields, data, data_index, api_type, version):
    payload = {}
    seen_fields = []
    for field in fields:
        if (api_type in fields_to_exclude_from_import_by_api_type_and_versions) and (field in
                                                                                         fields_to_exclude_from_import_by_api_type_and_versions[
                                                                                             api_type]) and (version in
                                                                                                                 fields_to_exclude_from_import_by_api_type_and_versions[
                                                                                                                     api_type][
                                                                                                                     field]):
            debug_log("The field " + field + " for objects of type " + api_type +
                      " is not supported in this version of the Web API (" + version + "). "
                                                                                       "Import request will ignore this field",
                      print_to_error_log=True)
            data_index += 1
            continue
        if "." not in field:
            if data[data_index] != "":
                payload[field] = data[data_index]
                if data[data_index] in ["TRUE", "FALSE"]:
                    payload[field] = payload[field].lower()
            data_index += 1
        else:
            main_field = field.split('.')[0]
            if main_field in seen_fields:
                continue
            seen_fields.append(main_field)
            main_field_with_dot = main_field + "."
            sub_fields = [x.split(".", 1)[1] for x in fields if x.startswith(main_field_with_dot)]
            sub_fields_prefix, sub_fields_suffix = sub_fields[0].split(".")[0], sub_fields[0].split(".")[1:]
            if sub_fields_prefix.isdigit():
                payload[main_field] = []
                if not sub_fields_suffix:
                    for _ in sub_fields:
                        if data[data_index] != "":
                            payload[main_field].append(data[data_index])
                        data_index += 1
                else:
                    list_items = split_list_items(sub_fields)
                    for list_item in list_items:
                        sub_payload, data_index = create_payload(list_item, data, data_index, api_type, version)
                        if sub_payload != {}:
                            payload[main_field].append(sub_payload)
                if not payload[main_field]:
                    payload.pop(main_field)
            else:
                sub_payload, data_index = create_payload(sub_fields, data, data_index, api_type, version)
                if sub_payload != {}:
                    payload[main_field] = sub_payload
    return payload, data_index


def check_for_export_error(general_object, client):
    if (general_object["type"] in partially_exportable_types or
                general_object["type"] not in singular_to_plural_dictionary[client.api_version]):

        prefix = "partial_" if general_object["type"] in partially_exportable_types else ""
        obj_name = ("_" + general_object["name"]) if ("name" in general_object and general_object["name"]) else ""
        new_name = prefix + "export_error_{0}_{1}{2}".format(general_object["type"], general_object["uid"], obj_name)
        if "name" in general_object:
            unexportable_objects_map[general_object["name"]] = new_name
        message_pattern = "Object of type {0} with uid {1}{2} is {3} exportable. " \
                          "Its name was changed to {4}"
        message = message_pattern.format(general_object["type"], general_object["uid"],
                                         (" named " + general_object["name"]) if (
                                             "name" in general_object and general_object["name"]) else "",
                                         "only partially"
                                         if general_object["type"] in partially_exportable_types else "not", new_name)

        debug_log(message, print_to_error_log=True)
        general_object["name"] = new_name


def count_global_layers(client, package):
    show_package_reply = client.api_call("show-package", payload={"name": package})
    if not show_package_reply.success:
        debug_log("Error analyzing package details! Aborting import.", True, True)
    access_layers = show_package_reply.data["access-layers"] if "access-layers" in show_package_reply.data else []
    threat_layers = show_package_reply.data["threat-layers"] if "threat-layers" in show_package_reply.data else []
    num_global_access = 0
    num_global_threat = 0
    for access_layer in access_layers:
        if access_layer["domain"]["domain-type"] == "global domain":
            num_global_access += 1
    for threat_layer in threat_layers:
        if threat_layer["domain"]["domain-type"] == "global domain":
            num_global_threat += 1
    return num_global_access, num_global_threat


ip_address = ["255", "1", "255", "1"]


def generate_new_dummy_ip_address():
    global ip_address
    result = ".".join(ip_address)
    ip_address[3] = str(int(ip_address[3]) + 1)
    return result


def generate_export_error_report():
    with open("export_error_log.elg", 'w') as exp_err_file:
        for err_msg in err_msgs:
            try:
                exp_err_file.write(err_msg)
            except UnicodeEncodeError:
                exp_err_file.write(err_msg.encode('utf-8'))


def generate_import_error_report():
    with open("import_error_log.elg", 'w') as exp_err_file:
        for err_msg in err_msgs:
            try:
                exp_err_file.write(err_msg)
            except UnicodeEncodeError:
                exp_err_file.write(err_msg.encode('utf-8'))
