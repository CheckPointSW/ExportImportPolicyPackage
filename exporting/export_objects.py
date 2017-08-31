from exporting.special_treatment_objects import handle_fields
from lists_and_dictionaries import no_export_fields_and_subfields, \
    singular_to_plural_dictionary, group_objects_field, placeholder_type_by_obj_type, \
    no_export_fields_by_api_type, special_treatment_types, no_export_fields
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
    layer_reply = client.api_call("show-" + api_type.split("-")[0] + "-layer", {"name": payload["name"]})
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
                          "applications-and-url-filtering": 'True',  # layer_data["applications-and-url-filtering"],
                          "mobile-access": layer_data["mobile-access"],
                          "firewall": layer_data["firewall"],
                          "type": "access-layer"}
        if compare_versions(client.api_version, "1.1") != -1:
            layer_settings["shared"] = layer_data["shared"]
            layer_settings["content-awareness"] = layer_data["content-awareness"]
        else:
            layer_settings["data-awareness"] = layer_data["data-awareness"]
    else:
        layer_settings = {"name": layer_data["name"],
                          "uid": layer_data["uid"],
                          "color": layer_data["color"],
                          "comments": layer_data["comments"],
                          "type": "threat-layer"}

    if "detect-using-x-forward-for" in layer_data:
        layer_settings["detect-using-x-forward-for"] = layer_data["detect-using-x-forward-for"]

    debug_log("Getting information from show-" + api_type)

    limit = 2
    offset = 0
    done = False
    seen_object_uids = []

    while not done:
        rulebase_reply = client.api_call("show-" + api_type, {"name": payload["name"], "limit": limit, "offset": offset,
                                                              "details-level": "full"})
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
            if not skipped_first_empty_section and "rule-number" not in rulebase_item and "to" not in rulebase_item:
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

        offset += limit

    for general_object in general_objects:
        string = ("##Show presented object of type {0} " + (
            "with name {1}" if "name" in general_object else "with no name")).format(
            general_object["type"], general_object["name"] if "name" in general_object else "")
        debug_log(string)
        if should_export(general_object):
            check_for_export_error(general_object, client)

    debug_log("Analysing rulebase items...")
    for rulebase_item in rulebase_items:
        if any(x in rulebase_item["type"] for x in ["access-rule", "threat-rule", "threat-exception"]):
            string = ("##Show presented independent rule of type {0} " + ("with name {1}" if "name" in rulebase_item
                                                                          else "with no name")).format(
                rulebase_item["type"], rulebase_item["name"] if "name" in
                                                                rulebase_item else "")
            debug_log(string)
            rulebase_rules.append(rulebase_item)
        elif "section" in rulebase_item["type"]:
            for rule in rulebase_item["rulebase"]:
                string = ("##Show presented dependent rule of type {0} under section {1} " + ("with name {2}" if
                          "name" in rule else "with no name")).format(rule["type"], rulebase_item["name"] if "name" in
                          rulebase_item else "???", rule["name"] if "name" in rule else "")
                debug_log(string)
                rulebase_rules.append(rule)

            string = ("##Show presented section of type {0} " + (
                      "with name {1}" if "name" in rulebase_item else "with no name")).format(rulebase_item["type"],
                      rulebase_item["name"] if "name" in rulebase_item else "")
            debug_log(string)
            rulebase_sections.append(rulebase_item)
        else:
            debug_log("Unsupported rulebase object type - '" + rulebase_item["type"] + "'. Continue...",
                      print_to_error_log=True)

    return layer_settings, rulebase_sections, rulebase_rules, general_objects


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

    format_and_merge_data(data_dict, object_dictionary)


def format_and_merge_data(data_dict, objects):
    global exported_objects
    unexported_objects = [x for x in objects if x["uid"] not in exported_objects]
    exported_objects.extend([x["uid"] for x in unexported_objects])
    formatted_data = format_objects(unexported_objects)
    merge_data(data_dict, formatted_data)


def format_objects(objects):
    formatted_objects = []

    for i in range(len(objects)):
        api_type = objects[i]["type"]
        if api_type in special_treatment_types:
            handle_fields(objects[i])
        flat_json = flatten_json(objects[i])

        string = u"Exporting {0} with uid {1} named {2}" if "name" in objects[i] else u"Exporting {0} with uid {1}"
        message = string.format(api_type, objects[i]["uid"], objects[i]["name"] if 'name' in objects[i] else "").encode(
            "utf-8")
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
    group_object = client.api_call("show-" + api_type, {"uid": group["uid"],
                                                        "details-level": "full"}).data

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
        debug_log("Exporting " + singular_to_plural_dictionary[client.api_version][api_type] + " from group [" + group[
            "name"] + "]", True)

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
            for field in obj.keys():
                sub_fields = field.split(".")
                if any(x for x in sub_fields if x in no_export_fields_and_subfields) or \
                        (sub_fields[0] in no_export_fields) or \
                        (api_type in no_export_fields_by_api_type and
                             any(x for x in sub_fields if x in no_export_fields_by_api_type[api_type])):
                    obj.pop(field, None)