import os

from export_objects import get_objects, \
    get_query_rulebase_data, format_and_merge_data, merge_data, \
    clean_objects, singular_to_plural_dictionary, format_and_merge_unexportable_objects, \
    replace_rule_field_uids_by_name, cleanse_object_dictionary, export_general_objects
from utils import debug_log, create_tar_file


def export_access_rulebase(package, layer, layer_uid, client, timestamp, tar_file):
    data_dict = {}

    debug_log("Exporting Access Layer [" + layer + "]", True)

    layer_settings, rulebase_sections, rulebase_rules, general_objects = \
        get_query_rulebase_data(client, "access-rulebase", {"name": layer, "uid": layer_uid, "package": package})

    if not layer_settings:
        return None, None

    object_dictionary, unexportable_objects, exportable_types = \
        get_objects(general_objects, client.api_version)

    to_position = None

    debug_log("Processing rules and sections", True)

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

    if "access-layer" in object_dictionary:
        for access_layer in object_dictionary["access-layer"]:
            debug_log("Exporting Inline-Layer [" + access_layer["name"] + "]", True)
            inner_data_dict, inner_unexportable_objects = \
                export_access_rulebase(package, access_layer["name"], access_layer["uid"], client, timestamp, tar_file)
            layer_tar_name = \
                create_tar_file(access_layer, inner_data_dict,
                                timestamp, ["access-rule", "access-section"], client.api_version)
            inner_data_dict.pop("access-rule", None)
            inner_data_dict.pop("access-section", None)
            merge_data(data_dict, inner_data_dict)
            merge_data(unexportable_objects, inner_unexportable_objects)
            tar_file.add(layer_tar_name)
            os.remove(layer_tar_name)

    for api_type in exportable_types:
        debug_log(
            "Exporting " + singular_to_plural_dictionary[client.api_version][api_type] + " from layer [" + layer + "]",
            True)
        export_general_objects(data_dict, api_type, object_dictionary[api_type], unexportable_objects, client)

    debug_log("Exporting access rules from layer [" + layer + "]", True)

    format_and_merge_data(data_dict, rulebase_rules)

    debug_log("Exporting access sections from layer [" + layer + "]", True)

    for rulebase_section in rulebase_sections:
        debug_log("rulebase_sections contains: " + (
                  rulebase_section["name"] if "name" in rulebase_section else "no-name section"))
    format_and_merge_data(data_dict, rulebase_sections)

    debug_log("Exporting placeholders for unexportable objects from layer [" + layer + "]", True)

    format_and_merge_unexportable_objects(data_dict, unexportable_objects)

    debug_log("Exporting layer settings of layer [" + layer + "]", True)

    format_and_merge_data(data_dict, [layer_settings])

    debug_log("Done exporting layer '" + layer + "'.\n", True)

    clean_objects(data_dict)

    return data_dict, unexportable_objects
