from export_objects import get_objects, \
    get_query_rulebase_data, format_and_merge_data, merge_data, \
    clean_objects, singular_to_plural_dictionary, format_and_merge_unexportable_objects, \
    replace_rule_field_uids_by_name, cleanse_object_dictionary, format_and_merge_exception_groups, \
    export_general_objects
from exporting.export_threat_exception_rulebase import export_threat_exception_rulebase
from utils import debug_log


def export_threat_rulebase(package, layer, layer_uid, client):
    data_dict = {}

    debug_log("Exporting Threat Layer [" + layer + "]", True)

    layer_settings, _, rulebase_rules, general_objects = \
        get_query_rulebase_data(client, "threat-rulebase", {"name": layer, "uid": layer_uid, "package": package})

    if not layer_settings:
        return None, None

    exception_groups = []

    object_dictionary, unexportable_objects, exportable_types = \
        get_objects(general_objects, client.api_version)

    debug_log("Processing rules and exceptions", True)

    for rulebase_rule in rulebase_rules:
        replace_rule_field_uids_by_name(rulebase_rule, general_objects)
        if "exceptions" in rulebase_rule:
            exceptions_data_dict, exceptions_unexportable_objects = \
                export_threat_exception_rulebase(package, layer, layer_uid, rulebase_rule, exception_groups, client)
            if not exceptions_data_dict:
                continue
            merge_data(data_dict, exceptions_data_dict)
            merge_data(unexportable_objects, exceptions_unexportable_objects)

    cleanse_object_dictionary(object_dictionary)

    for api_type in exportable_types:
        debug_log(
            "Exporting " + singular_to_plural_dictionary[client.api_version][api_type] + " from layer [" + layer + "]",
            True)
        export_general_objects(data_dict, api_type, object_dictionary[api_type], unexportable_objects, client)

    debug_log("Exporting threat rules from layer [" + layer + "]", True)

    format_and_merge_data(data_dict, rulebase_rules)

    debug_log("Exporting Exception-Groups used in layer [" + layer + "]", True)

    format_and_merge_exception_groups(data_dict, exception_groups)

    debug_log("Exporting placeholders for unexportable objects from layer [" + layer + "]", True)

    format_and_merge_unexportable_objects(data_dict, unexportable_objects)

    debug_log("Exporting layer settings of layer [" + layer + "]", True)

    format_and_merge_data(data_dict, [layer_settings])

    debug_log("Done exporting layer '" + layer + "'.\n", True)

    clean_objects(data_dict)

    return data_dict, unexportable_objects
