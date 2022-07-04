# plugin-adapter

### Deployment Process
Within the EXR ENV, use this general form:
```yaml
  plugin-adapter:
    image: blocknetdx/plugin-adapter
    restart: unless-stopped
    ports:
      - "5000:5000"
    environment:
      UTXO_PLUGIN_LIST: 'BLOCK:172.31.8.23,SYS:172.31.10.15'
    stop_signal: SIGINT
    stop_grace_period: 5m
    logging:
      driver: "json-file"
      options:
        max-size: "2m"
        max-file: "10"
    networks:
      backend:
        ipv4_address: 172.31.10.28
```
The UTXO_PLUGIN_LIST env var contains a list of all the coins for which utxo-plugin service is to be supported, and the backend network IP address of each of the corresponding utxo-plugin containers.
