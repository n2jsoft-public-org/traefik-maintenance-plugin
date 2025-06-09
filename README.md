# traefik-maintenance-plugin

A Traefik middleware plugin that restricts access to specified IP addresses and redirects unauthorized requests to a configurable URL. Ideal for maintenance mode or restricting environments by IP.


## Features

- IP whitelisting using CIDR or individual IPs (IPv4 and IPv6)
- Redirects unauthorized users to a redirectUrl
- Extracts client IP from X-Forwarded-For, X-Real-IP, or RemoteAddr

## Configuration

Add the plugin to your Traefik dynamic configuration (via file provider):

Example :

```yaml
http:
  middlewares:
    ip-whitelist-redirect:
      plugin:
        traefik_maintenance_plugin:
          redirectUrl: "https://maintenance.example.com"
          allowedIPs:
            - "192.168.1.100"
            - "10.0.0.0/8"
            - "2001:db8::/32"
          debug: true
```

## Development & Testing

Add maintenance.local to your `/etc/hosts` file and use docker-compose to run the plugin in a local Traefik instance:

```bash
docker-compose up
```


