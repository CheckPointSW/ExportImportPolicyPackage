from utils import debug_log


def handle_fields(obj):
    if obj["type"] == "threat-profile":
        new_items = {}
        old_keys = []
        for key in obj.keys():
            if key in ["extended-attributes-to-activate", "extended-attributes-to-deactivate"]:
                old_keys.append(key)
                new_key = "activate-protections-by-extended-attributes" if \
                    key == "extended-attributes-to-activate" else "deactivate-protections-by-extended-attributes"
                new_items[new_key] = []
                for index in range(len(obj[key])):
                    for sub_index in range(len(obj[key][index]["values"])):
                        new_items[new_key].append({"category": obj[key][index]["name"],
                                                   "name": obj[key][index]["values"][sub_index]["name"]})

            if key == "overrides":
                new_overrides = []
                for override in obj[key]:
                    protection = override["protection"]
                    override_obj = override["override"]

                    new_override = {"protection": protection}
                    for k, v in override_obj.items():
                        new_override[k] = v

                    new_overrides.append(new_override)

                obj[key] = new_overrides

                debug_log(f"threat profile overrides: {obj[key]}")
        for key in old_keys:
            obj.pop(key)
        for new_key, new_item in new_items.items():
            obj[new_key] = new_item
