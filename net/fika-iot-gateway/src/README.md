# init
* key path
* cert path
* thing name

# MQTT
## default subscribe topic from configure file(TOML, YAML or INI)

```
[[nmp.mqtt]]
subscribe = "topic"
```

## dynamic subscribe topic from redis

```sh
redis-cli publish nmp.mqtt.subscribe {topic}
```

## publish topic from redis

```sh
redis-cli publish nmp.mqtt.update.{topic} ......
```

# shadow
## default subscribe topic(property) from configure file(TOML, YAML or INI)

```
[[nmp.shadow]]
subscribe = "property"
```

## dynamic subscribe topic(property) from redis

```sh
redis-cli publish nmp.shadow.subscribe {property}
```

## publish topic(property) from redis

```sh
redis-cli publish nmp.shadow.update.{property} ......
```
