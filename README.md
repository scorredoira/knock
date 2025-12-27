# knock

Port knocking SSH firewall. Bloquea SSH (puerto 22) a todos excepto IPs autorizadas. Para añadir tu IP, haces "knock" autenticándote con tu clave SSH.

## Instalación

```bash
knock deploy user@servidor
```

Esto:
1. Compila y sube el binario
2. Instala el servicio systemd
3. Genera host key si no existe
4. Cierra el firewall
5. Añade tu IP a la whitelist

## Uso (cliente)

```bash
knock servidor      # Añade tu IP a la whitelist
knock git           # Usa alias de ~/.ssh/config
```

## Uso (servidor)

```bash
knock status        # Ver estado del firewall
knock list          # Listar IPs en whitelist
knock add 1.2.3.4   # Añadir IP manualmente
knock remove 1.2.3.4
knock clear         # Eliminar todas las IPs
knock open          # Abrir SSH a todos (desactivar)
knock close         # Cerrar SSH (activar)
```

## Puertos

- **22**: SSH - bloqueado excepto IPs whitelist
- **80/443**: HTTP/HTTPS - siempre abierto
- **722**: knock - siempre abierto (para autenticación)

## Archivos

- `/etc/knock/config.json` - configuración y lista de IPs
- `/etc/knock/host_key` - clave del servidor knock
- `/root/.ssh/authorized_keys` - claves públicas autorizadas para knock

## Cómo funciona

1. Cliente conecta al puerto 722 con SSH
2. Servidor verifica clave pública contra authorized_keys
3. Si OK, añade IP del cliente a iptables
4. Cliente puede conectar por SSH normal (puerto 22)
