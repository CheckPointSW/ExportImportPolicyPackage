import os

from exporting.export_objects import get_objects, \
    get_query_rulebase_data, format_and_merge_data, \
    clean_objects, singular_to_plural_dictionary, format_and_merge_unexportable_objects, \
    replace_rule_field_uids_by_name, cleanse_object_dictionary, export_general_objects
from utils import debug_log


def export_https_rulebase(package, layer, layer_uid, client):
    data_dict = {}

    debug_log("Exporting HTTPS Layer [" + layer + "]", True)

    layer_settings, rulebase_sections, rulebase_rules, general_objects = \
        get_query_rulebase_data(client, "https-rulebase", {"name": layer, "uid": layer_uid, "package": package})

    if not layer_settings:
        return None, None

    object_dictionary, unexportable_objects, exportable_types = \
        get_objects(general_objects, client.api_version)

    to_position = None

    debug_log("Processing https rules and sections", True)

    for rulebase_item in rulebase_sections + rulebase_rules:
        if "rule" in rulebase_item["type"]:
            replace_rule_field_uids_by_name(rulebase_item, general_objects)
        elif "section" in rulebase_item["type"]:
            if "from" in rulebase_item:
                rulebase_item["position"] = rulebase_item["from"]
            else:
                rulebase_item["position"] = to_position if to_position else "top"
            to_position = rulebase_item["to"] if "to" in rulebase_item else to_position

    cleanse_object_dictionary(object_dictionary)

    for api_type in exportable_types:
        debug_log(
            "Exporting " + singular_to_plural_dictionary[client.api_version][api_type] + " from layer [" + layer + "]",
            True)
        export_general_objects(data_dict, api_type, object_dictionary[api_type], unexportable_objects, client)

    debug_log("Exporting https rules from layer [" + layer + "]", True)

    format_and_merge_data(data_dict, rulebase_rules)

    debug_log("Exporting https sections from layer [" + layer + "]", True)

    for rulebase_section in rulebase_sections:
        debug_log("rulebase_sections contains: " + (
                  rulebase_section["name"] if "name" in rulebase_section else "no-name section"))
    format_and_merge_data(data_dict, rulebase_sections)

    debug_log("Exporting https placeholders for unexportable objects from layer [" + layer + "]", True)

    format_and_merge_unexportable_objects(data_dict, unexportable_objects)

    debug_log("Exporting https layer settings of layer [" + layer + "]", True)

    format_and_merge_data(data_dict, [layer_settings])

    debug_log("Done exporting https layer '" + layer + "'.\n", True)

    clean_objects(data_dict)

    return data_dict, unexportable_objects
