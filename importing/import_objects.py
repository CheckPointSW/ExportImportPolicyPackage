import csv
import os
import tarfile
import sys

from lists_and_dictionaries import singular_to_plural_dictionary, generic_objects_for_rule_fields, import_priority, https_blades_names_map
from utils import debug_log, create_payload, compare_versions, generate_new_dummy_ip_address

duplicates_dict = {}
position_decrements_for_sections = []
missing_parameter_set = set()
should_create_imported_nat_top_section = True
should_create_imported_nat_bottom_section = True
imported_nat_top_section_uid = None
name_collision_map = {}
changed_object_names_map = {}


def import_objects(file_name, client, changed_layer_names, package, layer=None, args=None):
    global position_decrements_for_sections

    export_tar = tarfile.open(file_name, "r:gz")
    export_tar.extractall()
    tar_files = export_tar.getmembers()

    general_object_files = [general_object_file for general_object_file in tar_files if
                            os.path.splitext(general_object_file.name)[1] == ".csv" or
                            os.path.splitext(general_object_file.name)[1] == ".json"]

    rulebase_object_files = [general_object_file for general_object_file in tar_files if
                             os.path.splitext(general_object_file.name)[1] == ".gz"]

    general_object_files.sort(compare_general_object_files)

    layers_to_attach = {"access": [], "threat": [], "https": []}

    if not general_object_files:
        debug_log("Nothing to import...", True)

    version_file_name = [f for f in tar_files if f.name == "version.txt"][0]
    with open(version_file_name.name, 'rb') as version_file:
        version = version_file.readline()
        api_versions = client.api_call("show-api-versions")
        if not api_versions.success:
            debug_log("Error getting versions! Aborting import. " + str(api_versions), True, True)
            sys.exit(1)
        if version in api_versions.data["supported-versions"]:
            client.api_version = version
        else:
            debug_log(
                "The version of the imported package doesn't exist in this machine! import with this machines latest version. ",
                True, True)

    for general_object_file in general_object_files:
        _, file_extension = os.path.splitext(general_object_file.name)
        if file_extension != ".csv":
            os.remove(general_object_file.name)
            continue
        api_call = general_object_file.name.split('__')[2]
        counter = 1
        position_decrement_due_to_rules = 0
        position_decrement_due_to_sections = 0
        generic_type = None
        data = []
        if "generic" in api_call:
            generic_type = api_call.split("-")[3]
            api_call = "-".join(api_call.split("-")[0:3])
        api_type = generic_type if generic_type else '-'.join(api_call.split('-')[1:])
        if api_type == "access-rule" or api_type == "https-rule":
            position_decrements_for_sections = []
        debug_log("Adding " + (singular_to_plural_dictionary[client.api_version][api_type].replace('_', ' ')
                               if api_type in singular_to_plural_dictionary[
            client.api_version] else "generic objects of type " + api_type), True)

        with open(general_object_file.name, 'rb') as csv_file:
            reader = csv.reader(csv_file)
            num_objects = len(list(reader)) - 1
            csv_file.seek(0)

            fields = next(reader)

            while True:
                line = next(reader, None)
                if line is None:
                    break
                line = [unicode(item, 'utf-8') for item in line]
                data.append(line)

        os.remove(general_object_file.name)

        for line in data:
            counter, position_decrement_due_to_rules = add_object(line, counter, position_decrement_due_to_rules,
                                                                  position_decrement_due_to_sections, fields, api_type,
                                                                  generic_type, layer, layers_to_attach,
                                                                  changed_layer_names, api_call, num_objects, client, args, package)

    for rulebase_object_file in rulebase_object_files:
        layer_type = rulebase_object_file.name.split("__")[1]
        layer_name = '__'.join(rulebase_object_file.name.split('__')[2:-1])
        if layer_name in changed_layer_names:
            layer_name = changed_layer_names[layer_name]
        debug_log("Importing " + layer_type.split('_')[0].capitalize() + "_" + layer_type.split('_')[1].capitalize() +
                  " [" + layer_name + "]", True)
        import_objects(rulebase_object_file.name, client, changed_layer_names, package, layer_name, args)
        os.remove(rulebase_object_file.name)

    return layers_to_attach


def add_object(line, counter, position_decrement_due_to_rule, position_decrement_due_to_section, fields, api_type,
               generic_type, layer, layers_to_attach,
               changed_layer_names, api_call, num_objects, client, args, package):
    global duplicates_dict
    global position_decrements_for_sections
    global missing_parameter_set
    global should_create_imported_nat_top_section
    global should_create_imported_nat_bottom_section
    global imported_nat_top_section_uid

    if "access-rule" in api_type or "https-rule" in api_type:
        position_decrements_for_sections.append(position_decrement_due_to_rule)

    payload, _ = create_payload(fields, line, 0, api_type, client.api_version)
    if args is not None and args.objects_suffix != "":
        add_suffix_to_objects(payload, api_type, args.objects_suffix)

    # for objects that had collisions, use new name in the imported package
    for field in ["members", "source", "destination"]:
        if field in payload:
            for i, member in enumerate(payload[field]):
                if member in name_collision_map:
                    payload[field][i] = name_collision_map[member]

    payload["ignore-warnings"] = True  # Useful for example when creating two hosts with the same IP

    if "nat-rule" in api_type:
        # For NAT rules, the 'package' parameter is the name of the policy package!!!
        if package is None:
            debug_log("Internal error: package name is unknown", True, True)
        payload["package"] = package
        # --- NAT rules specific logic ---
        # Importing only rules, without sections.
        # Rules marked as "__before_auto_rules = TRUE" will be imported at the TOP of the rulebase, inside a new section "IMPORTED UPPER RULES".
        # There is an additional new section "Original Upper Rules" at the bottom of "IMPORTED UPPER RULES".
        # Rules marked as "__before_auto_rules = FALSE" will be imported at the BOTTOM of the rulebase, inside a new section "IMPORTED LOWER RULES".
        # There will be no rule merges!!!
        before_auto_rules = payload["__before_auto_rules"]
        payload.pop("__before_auto_rules", None)
        if "true" in before_auto_rules:
            if should_create_imported_nat_top_section:
                should_create_imported_nat_top_section = False
                nat_section_payload = {}
                nat_section_payload["package"] = package
                nat_section_payload["position"] = "top"
                # --> we add the footer section first!!!
                nat_section_payload["name"] = "Original Upper Rules"
                client.api_call("add-nat-section", nat_section_payload)
                # <--
                nat_section_payload["name"] = "IMPORTED UPPER RULES"
                nat_section_reply = client.api_call("add-nat-section", nat_section_payload)
                if nat_section_reply.success:
                    imported_nat_top_section_uid = nat_section_reply.data["uid"]
            if imported_nat_top_section_uid is None:
                payload["position"] = "bottom"
            else:
                sub_payload = {}
                sub_payload["bottom"] = imported_nat_top_section_uid
                payload["position"] = sub_payload
        else:
            if should_create_imported_nat_bottom_section:
                should_create_imported_nat_bottom_section = False
                nat_section_payload = {}
                nat_section_payload["package"] = package
                nat_section_payload["position"] = "bottom"
                nat_section_payload["name"] = "IMPORTED LOWER RULES"
                client.api_call("add-nat-section", nat_section_payload)
            payload["position"] = "bottom"
    else:
        if "position" in payload:
            if "rule" in api_type:
                payload["position"] = str(int(payload["position"]) - position_decrement_due_to_rule)
                if payload["action"] == "Drop":
                    if "action-settings" in payload:
                        payload.pop("action-settings")
                    if "user-check" in payload:
                        if "frequency" in payload["user-check"]:
                            payload["user-check"].pop("frequency")
                        if "custom-frequency" in payload["user-check"]:
                            payload["user-check"].pop("custom-frequency")
                        if "confirm" in payload["user-check"]:
                            payload["user-check"].pop("confirm")
            if "section" in api_type:
                section_position_decrement = (position_decrements_for_sections[int(payload["position"]) - 1] if len(
                    position_decrements_for_sections) > 0 else 0) + position_decrement_due_to_section
                payload["position"] = str(int(payload["position"]) - section_position_decrement)
        if generic_type:
            payload["create"] = generic_type
        if "layer" in api_type:
            check_duplicate_layer(payload, changed_layer_names, api_type, client)
            if compare_versions(client.api_version, "1.1") != -1 and "https" not in api_type:
                payload["add-default-rule"] = "false"
            if layer is None:
                if "access-layer" in api_type:
                    #---> This code segment distinguishes between an inline layer and an ordered layer during import
                    is_ordered_access_control_layer = payload["__ordered_access_control_layer"]
                    payload.pop("__ordered_access_control_layer", None)
                    if "true" in is_ordered_access_control_layer:
                        layers_to_attach["access"].append(payload["name"])   # ordered access layer
                    #<--- end of code segment
                elif "threat-layer" in api_type:
                    layers_to_attach["threat"].append(payload["name"])
                elif "https-layer" in api_type:
                    layers_to_attach["https"].append(payload["name"])
        elif "rule" in api_type or "section" in api_type or \
                (api_type == "threat-exception" and "exception-group-name" not in payload):
            payload["layer"] = layer
            if args is not None and args.objects_suffix != "":
                payload["layer"] += args.objects_suffix
            if client.api_version != "1" and api_type == "access-rule" and "track-alert" in payload:
                payload["track"] = {}
                payload["track"]["alert"] = payload["track-alert"]
                payload.pop("track-alert", None)
        elif api_type == "exception-group" and "applied-threat-rules" in payload:
            for applied_rule in payload["applied-threat-rules"]:
                if applied_rule["layer"] in changed_layer_names.keys():
                    applied_rule["layer"] = changed_layer_names[applied_rule["layer"]]

    if "updatable-object" in api_type:
        updatable_object_payload = {}
        if "uid-in-updatable-objects-repository" in payload:
            updatable_object_payload["uid-in-updatable-objects-repository"] = payload[
                "uid-in-updatable-objects-repository"]
        elif "uid-in-data-center" in payload:
            updatable_object_payload["uid-in-updatable-objects-repository"] = payload["uid-in-data-center"]
        if "tags" in payload:
            updatable_object_payload["tags"] = payload["tags"]
        if "comments" in payload:
            updatable_object_payload["comments"] = payload["comments"]
        if "color" in payload:
            updatable_object_payload["color"] = payload["color"]
        payload = updatable_object_payload
    elif "https-rule" in api_type:
        if "blade" in payload and len(payload["blade"]) > 0:
            if len(payload["blade"]) == 1 and payload["blade"][0] == "All":
                del payload["blade"]
            else:
                exported_blades = payload["blade"]
                blades_to_import = []
                for blade in exported_blades:
                    if blade in https_blades_names_map:
                        blades_to_import.append(https_blades_names_map[blade])
                    else:
                        blades_to_import.append(blade)
                payload["blade"] = blades_to_import

    if "tags" in payload:
        exported_tags = payload["tags"]
        tags_to_import = []
        unresolved_tags = []
        for tag in exported_tags:
            tag_name = None
            if isinstance(tag, dict):
                if "name" in tag:
                    tag_name = str(tag["name"])

            if tag_name is None or tag_name == "":
                debug_log("Unknown tag name for object [{0}]".format(payload["name"]), True, True)
            else:
                add_tag_to_payload = False
                reply = client.api_call("show-tag", {"name": tag_name})
                if reply.success:
                    add_tag_to_payload = True
                elif "generic_err_object_not_found" in reply.data["code"]:
                    reply = client.api_call("add-tag", tag)
                    if reply.success:
                        add_tag_to_payload = True

                if add_tag_to_payload:
                    tags_to_import.append(tag_name)
                else:
                    unresolved_tags.append(tag_name)

        if len(unresolved_tags) > 0:
            debug_log("Failed to add tags {0} for object [{1}]".format(unresolved_tags, payload["name"]), True, True)

        if len(tags_to_import) > 0:
            payload["tags"] = tags_to_import

    api_reply = client.api_call(api_call, payload)

    if not api_reply.success and "name" in payload and "More than one object" in api_reply.error_message:
        i = 0
        original_name = payload["name"]
        while not api_reply.success:
            payload["name"] = "NAME_COLLISION_RESOLVED" + ("_" if i == 0 else "_%s_" % i) + original_name
            api_reply = client.api_call(api_call, payload)
            i += 1

            if i > 100:
                payload["name"] = original_name
                break

        if api_reply.success:
            debug_log("Object \"%s\" was renamed to \"%s\" to resolve the name collision"
                      % (original_name, payload["name"]), True, True)
            name_collision_map[original_name] = payload["name"]

    if not api_reply.success:
        if api_reply.data and "errors" in api_reply.data:
            error_msg = api_reply.data["errors"][0]["message"]
        elif api_reply.data and "warnings" in api_reply.data:
            error_msg = api_reply.data["warnings"][0]["message"]
        else:
            error_msg = api_reply.error_message
        log_err_msg = "Failed to import {0}{1}. Error: {2}".format(api_type, " with name [" + payload[
            "name"] + "]" if "name" in payload else "", error_msg)

        if "More than one object" in api_reply.error_message:
            log_err_msg = api_reply.error_message + ". Cannot import this object"

        if "Object is already imported. please use the existing object" in api_reply.error_message:
            return counter, position_decrement_due_to_rule

        if "rule" in api_type and (
                        "Requested object" in api_reply.error_message and "not found" in api_reply.error_message):
            field_value = api_reply.error_message.split("[")[1].split("]")[0]
            indices_of_field = [i for i, x in enumerate(line) if x == field_value]
            field_keys = [x for x in fields if fields.index(x) in indices_of_field]
            for field_key in field_keys:
                if field_key.split(".")[0] in generic_objects_for_rule_fields:
                    missing_obj_data = generic_objects_for_rule_fields[field_key.split(".")[0]]
                    missing_type = missing_obj_data[0]
                    mandatory_field = missing_obj_data[1] if len(missing_obj_data) > 1 else None
                    add_missing_command = "add-" + missing_type
                    new_name = "import_error_due_to_missing_fields_" + field_value.replace(" ", "_")
                    add_succeeded = True
                    if new_name not in missing_parameter_set:
                        missing_parameter_set.add(new_name)
                        add_missing_payload = {"name": new_name}
                        if mandatory_field == "port":
                            add_missing_payload["port"] = "8080"
                        elif mandatory_field == "ip-address":
                            add_missing_payload["ip-address"] = generate_new_dummy_ip_address()
                        add_missing_reply = client.api_call(add_missing_command, add_missing_payload)
                        if not add_missing_reply.success:
                            log_err_msg += "\nAlso failed to generate placeholder object: {0}".format(
                                add_missing_reply.error_message)
                            add_succeeded = False
                    if add_succeeded:
                        line[fields.index(field_key)] = new_name
                        return add_object(line, counter, position_decrement_due_to_rule,
                                          position_decrement_due_to_section, fields, api_type, generic_type, layer,
                                          layers_to_attach,
                                          changed_layer_names, api_call, num_objects, client, args, package)
        if "Invalid parameter for [position]" in api_reply.error_message:
            if "access-rule" in api_type or "https-rule" in api_type:
                position_decrement_due_to_rule += adjust_position_decrement(int(payload["position"]),
                                                                            api_reply.error_message)
            elif "access-section" in api_type or "https-section" in api_type:
                position_decrement_due_to_section += adjust_position_decrement(int(payload["position"]),
                                                                               api_reply.error_message)
            return add_object(line, counter, position_decrement_due_to_rule, position_decrement_due_to_section, fields,
                              api_type, generic_type, layer,
                              layers_to_attach,
                              changed_layer_names, api_call, num_objects, client, args, package)
        elif "is not unique" in api_reply.error_message and "name" in api_reply.error_message:
            field_value = api_reply.error_message.partition("name")[2].split("[")[1].split("]")[0]
            debug_log("Not unique name problem \"%s\" - changing payload to use UID instead." % field_value, True, True)
            obj_uid_found_and_used = False
            if field_value not in duplicates_dict:
                show_objects_reply = client.api_query("show-objects",
                                                     payload={"in": ["name", "\"" + field_value + "\""]})
                if show_objects_reply.success:
                    for obj in show_objects_reply.data:
                        if obj["name"] == field_value:
                            duplicates_dict[field_value] = obj["uid"]
                            obj_uid_found_and_used = True
            else:
                obj_uid_found_and_used = True
            if obj_uid_found_and_used:
                indices_of_field = [i for i, x in enumerate(line) if x == field_value]
                field_keys = [x for x in fields if fields.index(x) in indices_of_field]
                for field_key in field_keys:
                    line[fields.index(field_key)] = duplicates_dict[field_value]
                return add_object(line, counter, position_decrement_due_to_rule, position_decrement_due_to_section, fields,
                                  api_type, generic_type, layer, layers_to_attach,
                                  changed_layer_names, api_call, num_objects, client, args, package)
            else:
                debug_log("Not unique name problem \"%s\" - cannot change payload to use UID instead of name." % field_value, True, True)
        elif "will place the exception in an Exception-Group" in api_reply.error_message:
            return add_object(line, counter, position_decrement_due_to_rule - 1, position_decrement_due_to_section,
                              fields, api_type, generic_type, layer, layers_to_attach,
                              changed_layer_names, api_call, num_objects, client, args, package)

        position_decrement_due_to_rule += 1

        debug_log(log_err_msg, True, True)
        if args is not None and args.strict:
            discard_reply = client.api_call("discard")
            if not discard_reply.success:
                debug_log("Failed to discard changes! Terminating. Error: " +
                          discard_reply.error_message,
                          True, True)
            exit(1)
    else:
        imported_name = payload["name"] if "name" in payload else ""
        debug_log("Imported {0}{1}".format(api_type, " with name [" + imported_name.encode("utf-8") + "]"))
        if counter % 20 == 0 or counter == num_objects:
            percentage = int(float(counter) / float(num_objects) * 100)
            debug_log("Imported {0} out of {1} {2} ({3}%)".format(counter, num_objects,
                                                                  singular_to_plural_dictionary[client.api_version][
                                                                      api_type] if api_type in
                                                                                   singular_to_plural_dictionary[
                                                                                       client.api_version] else "generic objects",
                                                                  percentage), True)
            if counter % 100 == 0 or counter == num_objects:
                publish_reply = client.api_call("publish", wait_for_task=True)
                if not publish_reply.success:
                    plural = singular_to_plural_dictionary[client.api_version][api_type].replace('_', ' ') \
                        if api_type in singular_to_plural_dictionary[client.api_version] \
                        else "generic objects of type " + api_type
                    try:
                        debug_log("Failed to publish import of " + plural + " from tar file #" +
                                  str((counter / 100) + 1) + "! " + plural.capitalize() +
                                  " from said file were not imported!. Error: " + str(publish_reply.error_message),
                                  True, True)
                    except UnicodeEncodeError:
                        try:
                            debug_log("UnicodeEncodeError: " + str(publish_reply.error_message), True, True)
                        except:
                            debug_log("UnicodeEncodeError: .encode('utf-8') FAILED", True, True)

                    discard_reply = client.api_call("discard")
                    if not discard_reply.success:
                        debug_log("Failed to discard changes of unsuccessful publish! Terminating. Error: " +
                                  discard_reply.error_message,
                                  True, True)
                        exit(1)

    return counter + 1, position_decrement_due_to_rule


def adjust_position_decrement(position, error_message):
    indices_of_brackets = [i for i, letter in enumerate(error_message) if letter == '[' or letter == ']']
    valid_range = error_message[indices_of_brackets[4]:indices_of_brackets[5] + 1]
    _, _, final_position_with_bracket = valid_range.partition("-")
    final_position = final_position_with_bracket[:-1]
    return position - int(final_position)


def check_duplicate_layer(payload, changed_layer_names, api_type, client):
    layer_name = payload["name"]
    new_layer_name = payload["name"]

    i = 0
    while True:
        show_layer = client.api_call("show-" + api_type, payload={"name": new_layer_name})

        if "code" in show_layer.data and "not_found" in show_layer.data["code"]:
            if layer_name != new_layer_name:
                debug_log("A layer named \"%s\" already exists. Name was changed to \"%s\""
                          % (layer_name, new_layer_name))
                changed_layer_names[layer_name] = new_layer_name
                payload["name"] = new_layer_name
            break

        new_layer_name = "IMPORTED LAYER" + (" " if i == 0 else " %s " % i) + layer_name
        i += 1


def compare_general_object_files(file_a, file_b):
    api_type_a = "-".join(file_a.name.split("_")[4].split("-")[1:])
    api_type_b = "-".join(file_b.name.split("_")[4].split("-")[1:])
    priority_a = import_priority[api_type_a] if api_type_a in import_priority else 0
    priority_b = import_priority[api_type_b] if api_type_b in import_priority else 0
    if priority_b > priority_a:
        return -1
    elif priority_a > priority_b:
        return 1
    return 0

def add_suffix_to_objects(payload, api_type, objects_suffix):
    global changed_object_names_map
    ignore_types = ["updatable-object"]

    if api_type in ignore_types:
        return

    fields_to_change = ["name", "source", "destination", "service", "members", "inline-layer", "networks", "host",
                        "protected-scope", "protection-or-site", "exception-group-name", "rule-name"]
    for field in fields_to_change:
        if field in payload:
            if field == "name":
                oldName = payload[field]
                newName = oldName + objects_suffix
                payload[field] = newName
                changed_object_names_map[oldName] = newName
            elif field in ["source", "destination", "service", "members", "protected-scope", "protection-or-site"]:
                for i in range(len(payload[field])):
                    if payload[field][i] in changed_object_names_map:
                        payload[field][i] = changed_object_names_map[payload[field][i]]
            elif field in ["inline-layer", "host", "exception-group-name", "rule-name"]:
                if payload[field] in changed_object_names_map:
                    payload[field] = changed_object_names_map[payload[field]]
            elif field == "networks":
                for i in range(len(payload[field])):
                    if payload[field][i]["name"] in changed_object_names_map:
                        payload[field][i]["name"] = changed_object_names_map[payload[field][i]["name"]]
