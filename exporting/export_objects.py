from exporting.special_treatment_objects import handle_fields
from lists_and_dictionaries import no_export_fields_and_subfields, \
    singular_to_plural_dictionary, group_objects_field, placeholder_type_by_obj_type, \
    no_export_fields_by_api_type, special_treatment_types, \
    fields_to_convert_from_obj_to_identifier_by_api_type, fields_to_exclude_due_to_value_of_other_fields
from utils import debug_log, merge_data, flatten_json, find_min_position_group, compare_versions, \
    check_for_export_error, \
    generate_new_dummy_ip_address

exported_objects = []


def get_query_rulebase_data(client, api_type, payload):
    rulebase_items = []
    rulebase_sections = []
    rulebase_rules = []
    general_objects = []

    debug_log("Getting layer information for layer [" + payload["name"] + "]")
    # We use here uid instead of name for supporting MDS env.
    layer_reply = client.api_call("show-" + api_type.split("-")[0] + "-layer", {"uid": payload["uid"]})
    if not layer_reply.success:
        debug_log("Failed to retrieve layer named '" +
                  payload["name"] + "'! Error: " + str(layer_reply.error_message) +
                  ". Layer was not exported!", True, True)
        return None, None, None, None

    layer_data = layer_reply.data

    if layer_data["type"] == "access-layer":
        layer_settings = {"name": layer_data["name"],
                          "uid": layer_data["uid"],
                          "color": layer_data["color"],
                          "comments": layer_data["comments"],
                          "applications-and-url-filtering": 'True',
                          "mobile-access": layer_data["mobile-access"],
                          "firewall": layer_data["firewall"],
                          "type": "access-layer"}
        if compare_versions(client.api_version, "1.1") != -1:
            layer_settings["shared"] = layer_data["shared"]
            layer_settings["content-awareness"] = layer_data["content-awareness"]
        else:
            layer_settings["data-awareness"] = layer_data["data-awareness"]
    elif layer_data["type"] == "https-layer":
        layer_settings = {"name": layer_data["name"],
                          "uid": layer_data["uid"],
                          "color": layer_data["color"],
                          "comments": layer_data["comments"],
                          "shared": layer_data["shared"],
                          "type": "https-layer"}
        if "layer-type" in layer_data:
            layer_settings["layer-type"] = layer_data["layer-type"]
    else:
        layer_settings = {"name": layer_data["name"],
                          "uid": layer_data["uid"],
                          "color": layer_data["color"],
                          "comments": layer_data["comments"],
                          "type": "threat-layer"}

    if "detect-using-x-forward-for" in layer_data:
        layer_settings["detect-using-x-forward-for"] = layer_data["detect-using-x-forward-for"]

    debug_log("Getting information from show-" + api_type)

    seen_object_uids = []

    # We use here uid instead of name for supporting MDS env.
    queryPayload = {"uid": payload["uid"], "package": payload["package"]}
    if api_type == "threat-rule-exception-rulebase":
        queryPayload = {"uid": payload["uid"], "package": payload["package"], "rule-uid": payload["rule-uid"]}

    rulebase_replies = client.gen_api_query("show-" + api_type, details_level="full", container_keys=["rulebase"], payload=queryPayload)

    for rulebase_reply in rulebase_replies:
        if not rulebase_reply.success:
            debug_log("Failed to retrieve layer named '" +
                      payload["name"] + "'! Error: " + str(rulebase_reply.error_message) +
                      ". Layer was not exported!", True, True)
            return None, None, None, None
        rulebase_data = rulebase_reply.data
        if "total" not in rulebase_data or rulebase_data["total"] == 0:
            break
        if rulebase_data["to"] == rulebase_data["total"]:
            done = True
        percentage_complete = int((float(rulebase_data["to"]) / float(rulebase_data["total"])) * 100)
        debug_log("Retrieved " + str(rulebase_data["to"]) +
                  " out of " + str(rulebase_data["total"]) + " rules (" + str(percentage_complete) + "%)", True)

        non_empty_rulebase_items = []
        skipped_first_empty_section = False
        for rulebase_item in rulebase_data["rulebase"]:
            if not skipped_first_empty_section and "rule-number" not in rulebase_item and "to" not in rulebase_item and rulebase_item["type"] != "threat-section":
                continue
            else:
                skipped_first_empty_section = True
            non_empty_rulebase_items.append(rulebase_item)
            if ("rule-number" in rulebase_item and rulebase_item["rule-number"] == rulebase_data["to"]) or (
                            "to" in rulebase_item and rulebase_item["to"] == rulebase_data["to"]):
                break

        if non_empty_rulebase_items and rulebase_items and non_empty_rulebase_items[0]["uid"] == \
                rulebase_items[len(rulebase_items) - 1]["uid"]:
            rulebase_items[len(rulebase_items) - 1]["rulebase"].extend(non_empty_rulebase_items[0]["rulebase"])
            rulebase_items[len(rulebase_items) - 1]["to"] = non_empty_rulebase_items[0]["to"]
            non_empty_rulebase_items = non_empty_rulebase_items[1:]
        rulebase_items.extend(non_empty_rulebase_items)

        new_objects = [x for x in rulebase_data["objects-dictionary"] if x["uid"] not in seen_object_uids]
        seen_object_uids.extend([x["uid"] for x in new_objects])
        general_objects.extend(new_objects)

    for general_object in general_objects:
        string = (u"##Show presented object of type {0} " + (
            u"with name {1}" if "name" in general_object else u"with no name")).format(
            general_object["type"], general_object["name"] if "name" in general_object else "")
        debug_log(string)
        if should_export(general_object):
            check_for_export_error(general_object, client)

    debug_log("Analysing rulebase items...")
    for rulebase_item in rulebase_items:
        if any(x in rulebase_item["type"] for x in ["access-rule", "threat-rule", "threat-exception", "https-rule"]):
            string = (u"##Show presented independent rule of type {0} "
                      + (u"with name {1}" if "name" in rulebase_item else u"with no name")).format(
                rulebase_item["type"],
                rulebase_item["name"] if "name" in rulebase_item else "")
            debug_log(string)
            rulebase_rules.append(rulebase_item)
        elif "section" in rulebase_item["type"]:
            for rule in rulebase_item["rulebase"]:
                string = (u"##Show presented dependent rule of type {0} under section {1} " + (u"with name {2}" if
                                                                                               "name" in rule else u"with no name")).format(
                    rule["type"], rulebase_item["name"] if "name" in
                                                           rulebase_item else "???",
                    rule["name"] if "name" in rule else "")
                debug_log(string)
                rulebase_rules.append(rule)

            # Because of 50 items chunks per API query reply, one rule section may spread over several chunks!!!
            if rulebase_sections and rulebase_sections[len(rulebase_sections) - 1]["uid"] == rulebase_item["uid"]:
                if "to" in rulebase_item:
                    rulebase_sections[len(rulebase_sections) - 1]["to"] = rulebase_item["to"]
                continue

            string = (u"##Show presented section of type {0} " + (
                u"with name {1}" if "name" in rulebase_item else u"with no name")).format(
                    rulebase_item["type"], rulebase_item["name"] if "name" in rulebase_item else "")
            debug_log(string)
            rulebase_sections.append(rulebase_item)
        else:
            debug_log("Unsupported rulebase object type - '" + rulebase_item["type"] + "'. Continue...",
                      print_to_error_log=True)

    return layer_settings, rulebase_sections, rulebase_rules, general_objects


def get_query_nat_rulebase_data(client, payload):
    rulebase_items = []
    rulebase_rules = []
    general_objects = []
    seen_object_uids = []
    before_auto_rules = True

    debug_log("Getting information from show-nat-rulebase", True)

    rulebase_replies = client.gen_api_query("show-nat-rulebase", details_level="full", container_keys=["rulebase"], payload=payload)

    for rulebase_reply in rulebase_replies:
        if not rulebase_reply.success:
            debug_log("Failed to retrieve NAT rulebase! Error: " + str(rulebase_reply.error_message) +
                      ". NAT rulebase was not exported!", True, True)
            return None, None
        rulebase_data = rulebase_reply.data
        if "total" not in rulebase_data or rulebase_data["total"] == 0:
            break
        percentage_complete = int((float(rulebase_data["to"]) / float(rulebase_data["total"])) * 100)
        debug_log("Retrieved " + str(rulebase_data["to"]) +
                  " out of " + str(rulebase_data["total"]) + " rules (" + str(percentage_complete) + "%)", True)

        non_empty_rulebase_items = []
        for rulebase_item in rulebase_data["rulebase"]:
            if "nat-section" in rulebase_item["type"]:
                # Skip system auto generated section
                if "Automatic Generated Rules : " in rulebase_item["name"]:
                    before_auto_rules = False
                    continue
                # Skip empty section (no rules inside...)
                if "from" not in rulebase_item:
                    continue
            rulebase_item["__before_auto_rules"] = before_auto_rules
            non_empty_rulebase_items.append(rulebase_item)
            if ("to" in rulebase_item and rulebase_item["to"] == rulebase_data["to"]):
                break

        if non_empty_rulebase_items and rulebase_items and non_empty_rulebase_items[0]["uid"] == \
                rulebase_items[len(rulebase_items) - 1]["uid"]:
            rulebase_items[len(rulebase_items) - 1]["rulebase"].extend(non_empty_rulebase_items[0]["rulebase"])
            rulebase_items[len(rulebase_items) - 1]["to"] = non_empty_rulebase_items[0]["to"]
            non_empty_rulebase_items = non_empty_rulebase_items[1:]
        rulebase_items.extend(non_empty_rulebase_items)

        new_objects = [x for x in rulebase_data["objects-dictionary"] if x["uid"] not in seen_object_uids]
        seen_object_uids.extend([x["uid"] for x in new_objects])
        general_objects.extend(new_objects)

    for general_object in general_objects:
        string = (u"##Show presented object of type {0} " + (
            u"with name {1}" if "name" in general_object else u"with no name")).format(
            general_object["type"], general_object["name"] if "name" in general_object else "")
        debug_log(string)
        if should_export(general_object):
            check_for_export_error(general_object, client)

    debug_log("Analysing rulebase items...")
    for rulebase_item in rulebase_items:
        if "nat-rule" in rulebase_item["type"]:
            string = (u"##Show presented independent rule of type {0}").format(rulebase_item["type"])
            debug_log(string)
            rulebase_item.pop("auto-generated", None)
            rulebase_rules.append(rulebase_item)
        elif "nat-section" in rulebase_item["type"]:
            # !!! Attention: exporting only NAT rules, without sections !!!
            for rule in rulebase_item["rulebase"]:
                string = (u"##Show presented dependent rule of type {0} under section {1}").format(
                    rule["type"], rulebase_item["name"] if "name" in rulebase_item else "???")
                debug_log(string)
                rule.pop("auto-generated", None)
                rule["__before_auto_rules"] = rulebase_item["__before_auto_rules"]
                rulebase_rules.append(rule)

            string = (u"##Show presented section of type {0} " + (
                u"with name {1}" if "name" in rulebase_item else u"with no name")).format(
                    rulebase_item["type"], rulebase_item["name"] if "name" in rulebase_item else "")
            debug_log(string)
        else:
            debug_log("Unsupported NAT rulebase object type - '" + rulebase_item["type"] + "'. Continue...",
                      print_to_error_log=True)

    return rulebase_rules, general_objects


def replace_rule_field_uids_by_name(rule, general_objects):
    # This 'if' prevents the rare situations where this method is called on the same rule more than once
    if "position" in rule:
        return
    debug_log("Updating data for rule #" + str(rule["rule-number"]))
    rule["position"] = rule["rule-number"]
    rule.pop("rule-number")
    replace_data(rule, general_objects)


def replace_exception_data(exception, general_objects, layer=None,
                           rule_number=None, group=None, position_in_group=None):
    if "position" in exception:
        return
    position = position_in_group if not layer else exception["exception-number"]
    debug_log("Updating data for rule #" + str(position))
    exception["position"] = position
    if not layer:
        exception["exception-group-name"] = group
        if "rule-number" in exception:
            exception.pop("rule-number")
    elif "exception-group-name" not in exception:
        exception["rule-number"] = rule_number
    if "exception-number" in exception:
        exception.pop("exception-number")
    replace_data(exception, general_objects)


def replace_data(obj, general_objects):
    if isinstance(obj, dict):
        itr = obj.keys()
    elif isinstance(obj, list):
        itr = range(0, len(obj))
    else:
        itr = None

    if itr is not None:
        for key in itr:
            obj[key] = replace_data(obj[key], general_objects)
    else:
        replacement = next((x for x in general_objects if x["uid"] == obj), None)
        if replacement:
            name = replacement["cpmiDisplayName"] if "cpmiDisplayName" in replacement else replacement["name"]
            obj = name if name != "Inner Layer" else "Apply Layer"

    return obj


def should_export(obj):
    if "name" in obj and obj["name"] == "ThreatStandardSubRulebase":
        return False
    # TODO AdamG consider using domain-type
    return "domain" in obj and obj["domain"]["domain-type"] in ["domain", "global domain"]


def get_objects(raw_data, version):
    object_dictionary = {}
    exportable_types = set()
    unexportable_objects = []
    for obj in raw_data:
        if not should_export(obj):
            continue
        api_type = obj["type"]
        if api_type in singular_to_plural_dictionary[version]:
            if obj["type"] in object_dictionary:
                object_dictionary[obj["type"]].append(obj)
            else:
                object_dictionary[obj["type"]] = [obj]
            if "layer" not in api_type:
                exportable_types.add(api_type)
        else:
            unexportable_objects.append(obj)

    return object_dictionary, unexportable_objects, exportable_types


def export_general_objects(data_dict, api_type, object_dictionary, unexportable_objects, client):
    new_object_dictionary = []
    if api_type in group_objects_field.keys():
        for group_object in object_dictionary:
            full_group_objects = get_group_objects(data_dict,
                                                   api_type, group_object, client, unexportable_objects)
            for full_group_object in full_group_objects:
                for container in group_objects_field[full_group_object["type"]]:
                    full_group_object[container] = [x["name"] for x in full_group_object[container]]
                new_object_dictionary.append(full_group_object)

    if new_object_dictionary:
        object_dictionary = new_object_dictionary

    format_and_merge_data(data_dict, object_dictionary, client)


# tag_info_client - to handle objects with 'tags' field as list of uids
def format_and_merge_data(data_dict, objects, tag_info_client=None):
    global exported_objects
    unexported_objects = [x for x in objects if x["uid"] not in exported_objects or x["type"] == "exception-group"]
    exported_objects.extend([x["uid"] for x in unexported_objects])
    if tag_info_client:
        formatted_data = format_objects(unexported_objects, tag_info_client)
    else:
        formatted_data = format_objects(unexported_objects)
    merge_data(data_dict, formatted_data)


# tag_info_client - to handle objects with 'tags' field as list of uids
def format_objects(objects, tag_info_client=None):
    formatted_objects = []

    for i in range(len(objects)):
        api_type = objects[i]["type"]
        if api_type in special_treatment_types:
            handle_fields(objects[i])

        # when 'tags' field of object is a list of uids
        # for each uid, replace it with the full info of the tag - using "show-tag"
        if tag_info_client:
            for j in range(len(objects[i].get('tags', []))):
                if "name" not in objects[i]['tags'][j]:
                    tag_object_reply = tag_info_client.api_call("show-tag",
                                                                {"uid": objects[i]['tags'][j],
                                                                 "details-level": "full"})
                    if not tag_object_reply.success:
                        debug_log("Failed to retrieve tag info for object named '" +
                                  objects[i]["name"] + "'! Error: " + str(tag_object_reply.error_message) +
                                  ".", True, True)
                        continue

                    objects[i]['tags'][j] = tag_object_reply.data
        flat_json = flatten_json(objects[i])

        # Special handling for data-center-object types - prepare the data for the import!
        if "data-center-object" in api_type:
            if "data-center.name" in flat_json.keys():
                flat_json["data-center-name"] = flat_json["data-center.name"]

        string = u"Exporting {0} with uid {1} named {2}" if "name" in objects[i] else u"Exporting {0} with uid {1}"
        message = string.format(api_type, objects[i]["uid"], objects[i]["name"] if 'name' in objects[i] else "")
        debug_log(message)

        formatted_objects.append(flat_json)

    return formatted_objects


def format_and_merge_unexportable_objects(data_dict, unexportable_objects):
    formatted_objects = []

    for unexportable_object in unexportable_objects:
        placeholder = {"name": unexportable_object["name"]}
        for unexportable_obj_type in placeholder_type_by_obj_type.keys():
            if unexportable_obj_type in unexportable_object["type"]:
                for field in placeholder_type_by_obj_type[unexportable_obj_type]:
                    field_value = placeholder_type_by_obj_type[unexportable_obj_type][field]
                    if field_value:
                        placeholder[field] = placeholder_type_by_obj_type[unexportable_obj_type][field]
                    else:
                        placeholder[field] = generate_new_dummy_ip_address()
        if "type" not in placeholder:
            placeholder["type"] = "group"
        formatted_objects.append(placeholder)
        if placeholder["type"] in data_dict:
            data_dict[placeholder["type"]].insert(0, placeholder)
        else:
            data_dict[placeholder["type"]] = [placeholder]


def get_group_objects(data_dict, api_type, group, client, unexportable_objects):
    group_object_reply = client.api_call("show-" + api_type, {"uid": group["uid"], "details-level": "full"})
    if not group_object_reply.success:
        debug_log("Failed to retrieve group named '" +
                  group["name"] + "'! Error: " + str(group_object_reply.error_message) +
                  ". Group was not exported!", True, True)
        return []

    group_object = group_object_reply.data

    if api_type == "group-with-exclusion":
        include_group_object = None
        exclude_group_object = None
        if "include" in group_object:
            if group_object["include"]["type"] != "CpmiAnyObject":
                include_group_object = get_group_objects(data_dict, group_object["include"]["type"],
                                                         group_object["include"], client, unexportable_objects)
            group_object["include"] = group_object["include"]["name"]
        if "except" in group_object:
            if group_object["except"]["type"] != "CpmiAnyObject":
                exclude_group_object = get_group_objects(data_dict, group_object["except"]["type"],
                                                         group_object["except"], client, unexportable_objects)
            group_object["except"] = group_object["except"]["name"]
        return_list = [group_object]
        if include_group_object:
            return_list.extend(include_group_object)
        if exclude_group_object:
            return_list.extend(exclude_group_object)
        return return_list

    member_objects = []
    for container in group_objects_field[api_type]:
        member_objects.extend(group_object[container])

    object_dictionary, group_unexportable_objects, exportable_types = \
        get_objects(member_objects, client.api_version)

    for member_object in member_objects:
        if should_export(member_object):
            check_for_export_error(member_object, client)

    merge_data(unexportable_objects, group_unexportable_objects)

    for unexportable_object in unexportable_objects:
        for container in group_objects_field[api_type]:
            for member in group_object[container]:
                if unexportable_object["uid"] == member["uid"]:
                    member["name"] = unexportable_object["name"]
                    break

    for api_type in exportable_types:
        debug_log("Exporting " + singular_to_plural_dictionary[client.api_version][api_type] + 
                  " from group [" + group["name"] + "]", True)
        export_general_objects(data_dict, api_type, object_dictionary[api_type], unexportable_objects, client)

    return [group_object]


def format_and_merge_exception_groups(data_dict, exception_groups):
    sorted_exception_groups = []
    while exception_groups:
        sorted_exception_groups.append(find_min_position_group(exception_groups))
    for exception_group in sorted_exception_groups:
        exception_group.pop('positions')
    format_and_merge_data(data_dict, sorted_exception_groups)


# TODO AdamG
def cleanse_object_dictionary(object_dictionary):
    for api_type in object_dictionary:
        for obj in object_dictionary[api_type]:
            if not should_export(obj):
                object_dictionary[api_type].remove(obj)


def clean_objects(data_dict):
    for api_type in data_dict:
        for obj in data_dict[api_type]:
            # currently fields_to_exclude_due_to_value_of_other_fields is relevant only for the types below. if there'll
            # be more relevant types should change fields_to_exclude_due_to_value_of_other_fields to be by_api_type
            if api_type == 'simple-cluster' or api_type == 'simple-gateway' or 'service' in api_type:
                for dependent_field in fields_to_exclude_due_to_value_of_other_fields:
                    if dependent_field in obj:
                        # for each dependant field, in the presence of any of it's independent fields in the object with
                        # the same value as in the dict, the dependant field is removed
                        for independent_field in fields_to_exclude_due_to_value_of_other_fields[dependent_field].keys():
                            if independent_field in obj and obj[independent_field] == fields_to_exclude_due_to_value_of_other_fields[dependent_field][independent_field]:
                                obj.pop(dependent_field, None)
                                debug_log("The field " + dependent_field + " was removed from object of type " +
                                          api_type + " named " + obj["name"] + " since it cannot be present when the "
                                          "value of " + independent_field + " is " + str(obj[independent_field]))
                                break

            # converted_fields_to_add = {}
            for field in list(obj):
                sub_fields = field.split(".")
                # in cases where the request is a single value (e.g name/list of names) and the reply is the corresponding object/s, we wish to create
                # a new field named same as the object with the identifier as its value (and delete the rest of the object's fields!)
                if api_type in fields_to_convert_from_obj_to_identifier_by_api_type:
                    field_removed = False
                    for field_to_convert in fields_to_convert_from_obj_to_identifier_by_api_type[api_type]:
                        if field.startswith(field_to_convert + "."):
                            # check whether the field is the name of an object (might be an object in a list)
                            # if field == field_to_convert + ".name" or \
                            #         (field_to_convert + "." + sub_fields[-2] + ".name" == field and sub_fields[-2].isnumeric()):
                            #     identifier = obj[field]
                            #     converted_field = field[:-5]  # in cases of list of objects (remove .name)
                            #     converted_fields_to_add[converted_field] = identifier
                            obj.pop(field, None)
                            field_removed = True
                            debug_log("The field " + field + " was removed from object of type " + api_type + " named "
                                      + obj["name"] + " since we don't support the export of " + field_to_convert)
                            # todo - when converted_fields can be imported successfully change reason in debug info above
                            break
                    if field_removed:
                        continue  # Already handled the field so the code below is irrelevant

                local_no_export_fields_and_subfields = list(no_export_fields_and_subfields)
                if api_type == "time":
                    # For time objects, these two fields are required and must be retained!
                    local_no_export_fields_and_subfields.remove("from")
                    local_no_export_fields_and_subfields.remove("to")
                if field == "track.type":
                    # This field is required and must be retained since it defines whether tracking is enabled!
                    local_no_export_fields_and_subfields.remove("type")
                if api_type == "exception-group":
                    local_no_export_fields_and_subfields.remove("layer")

                if any(x for x in sub_fields if x in local_no_export_fields_and_subfields) or \
                        (api_type in no_export_fields_by_api_type and (
                                any(x for x in sub_fields if x in no_export_fields_by_api_type[api_type])
                                or field in no_export_fields_by_api_type[api_type])):
                    obj.pop(field, None)

            # todo - uncomment code below and converted_fields vars above when the converted_fields objects
            #  can be imported successfully. Currently if the converted_field is a created object, the server importing
            #  the data needs to create this object as well but this object isn't exported in a file so as a result we
            #  can get a bad link error when importing
            # for converted_field in converted_fields_to_add:
            #     obj[converted_field] = converted_fields_to_add[converted_field]
