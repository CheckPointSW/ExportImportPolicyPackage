from export_objects import get_objects, \
    get_query_rulebase_data, format_and_merge_data, clean_objects, singular_to_plural_dictionary, \
    format_and_merge_unexportable_objects, \
    cleanse_object_dictionary, replace_exception_data, export_general_objects
from utils import debug_log


def export_threat_exception_rulebase(package, layer, layer_uid, threat_rule, exception_groups, client):
    data_dict = {}

    debug_log("Exporting Exception-Rulebase from Threat-Rule #" +
              str(threat_rule["position"]) + " in Threat-Layer[" + layer + "]", True)

    layer_settings, rulebase_sections, rulebase_rules, general_objects = \
        get_query_rulebase_data(client, "threat-rule-exception-rulebase",
                                {"name": layer, "uid": layer_uid, "package": package, "rule-uid": threat_rule["uid"]})

    if not layer_settings:
        return None, None

    object_dictionary, unexportable_objects, exportable_types = \
        get_objects(general_objects, client.api_version)

    to_position = None

    debug_log("Processing exceptions", True)

    for rulebase_object in rulebase_sections + rulebase_rules:
        if "exception" in rulebase_object["type"]:
            replace_exception_data(rulebase_object, general_objects, layer=layer, rule_number=threat_rule["position"])
        elif "section" in rulebase_object["type"]:
            position_in_group = 1
            for rule in rulebase_object["rulebase"]:
                replace_exception_data(rule, general_objects,
                                       group=rulebase_object["name"], position_in_group=position_in_group)
                position_in_group += 1
            if rulebase_object["name"] == "Global Exceptions":
                continue
            show_group_reply = client.api_call("show-exception-group", payload={"name": rulebase_object["name"]})
            if rulebase_object["from"]:
                group_position = rulebase_object["from"]
            else:
                group_position = to_position if to_position else "top"
            to_position = rulebase_object["to"] if rulebase_object["to"] else to_position
            if rulebase_object["name"] not in [x["name"] for x in exception_groups]:
                show_group_reply.data["positions"] = []
                if show_group_reply.data["apply-on"] == "manually-select-threat-rules":
                    show_group_reply.data["applied-threat-rules"] = []
                exception_groups.append(show_group_reply.data)
            group_index = next(index for (index, d)
                               in enumerate(exception_groups) if d['name'] == show_group_reply.data['name'])
            exception_groups[group_index]["positions"].append(group_position)
            if exception_groups[group_index]["apply-on"] == "manually-select-threat-rules":
                exception_groups[group_index]["applied-threat-rules"].append(
                    {"layer": layer, "rule-number": str(threat_rule["position"])})

    cleanse_object_dictionary(object_dictionary)

    for api_type in exportable_types:
        debug_log(
            "Exporting " + singular_to_plural_dictionary[client.api_version][api_type] + " from layer [" + layer + "]",
            True)
        export_general_objects(data_dict, api_type, object_dictionary[api_type], unexportable_objects, client)

    debug_log("Exporting threat exceptions from layer [" + layer + "]", True)

    format_and_merge_data(data_dict, rulebase_rules)

    debug_log("Exporting placeholders for unexportable objects from layer [" + layer + "]", True)

    format_and_merge_unexportable_objects(data_dict, unexportable_objects)

    debug_log("Exporting layer settings of layer [" + layer + "]", True)

    format_and_merge_data(data_dict, [layer_settings])

    debug_log("Done exporting layer '" + layer + "'.\n", True)

    clean_objects(data_dict)

    return data_dict, unexportable_objects
