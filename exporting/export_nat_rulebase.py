import os

from export_objects import get_objects, \
    get_query_nat_rulebase_data, format_and_merge_data, merge_data, \
    clean_objects, singular_to_plural_dictionary, format_and_merge_unexportable_objects, \
    replace_rule_field_uids_by_name, cleanse_object_dictionary, export_general_objects
from utils import debug_log, create_tar_file


def export_nat_rulebase(package, client):
    data_dict = {}

    rulebase_rules, general_objects = get_query_nat_rulebase_data(client, {"package": package})

    object_dictionary, unexportable_objects, exportable_types = get_objects(general_objects, client.api_version)

    debug_log("Processing rules and sections", True)

    for rule in rulebase_rules:
        replace_rule_field_uids_by_name(rule, general_objects)

    cleanse_object_dictionary(object_dictionary)

    for api_type in exportable_types:
        debug_log("Exporting " + singular_to_plural_dictionary[client.api_version][api_type], True)
        export_general_objects(data_dict, api_type, object_dictionary[api_type], unexportable_objects, client)

    debug_log("Exporting NAT rules", True)

    format_and_merge_data(data_dict, rulebase_rules)

    debug_log("Exporting placeholders for unexportable objects from NAT rulebase", True)

    format_and_merge_unexportable_objects(data_dict, unexportable_objects)

    debug_log("Done exporting NAT rulebase.\n", True)

    clean_objects(data_dict)

    return data_dict, unexportable_objects
