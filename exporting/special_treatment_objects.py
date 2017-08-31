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
        for key in old_keys:
            obj.pop(key)
        for new_key, new_item in new_items.iteritems():
            obj[new_key] = new_item
