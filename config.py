def get(value, default=None):
    import yaml
    with open("config.yml", 'r') as stream:
        try:
            result = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            return default
    if value:
        value = value.split('.')
    for i in value:
        try:
            result = result[i]
        except KeyError:
            return default
    return result


### Add support for unvalid values ###
