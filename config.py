def get(value, default=None):
    import yaml
    try:
        with open("config.yml", 'r') as stream:
            try:
                result = yaml.safe_load(stream)
            except yaml.YAMLError:
                return default
        if value:
            value = value.split('.')
        for i in value:
            try:
                result = result[i]
            except KeyError:
                return default
        return result
    except FileNotFoundError:
        return default

if __name__ == '__main__':
    print(get('slack.channel', 'Err'))
    print(get('slck.cannel', 'Err'))
