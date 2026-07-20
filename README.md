# knock

Port knocking firewall. Los puertos protegidos (SSH y demás) están bloqueados a
todo el mundo excepto a las IPs autorizadas. Para añadir tu IP haces "knock",
autenticándote con tu clave SSH contra el puerto 722.

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

La clave del servidor se fija en el primer knock (TOFU) y se guarda en
`~/.knock/known_hosts.json`. Si cambia, el knock falla — borra la entrada si has
reinstalado el servidor.

## Uso (servidor)

```bash
knock status        # Ver estado, puertos públicos y protegidos
knock list          # Listar IPs en whitelist
knock add 1.2.3.4   # Añadir IP manualmente
knock remove 1.2.3.4
knock clear         # Eliminar todas las IPs
knock open          # Desactivar el firewall (vía de escape)
knock close         # Activar el firewall
```

## Puertos

Configurables en `/etc/knock/config.json`:

- `publicPorts` — abiertos a todo el mundo. Por defecto **80, 443**
- `protectedPorts` — solo desde IPs de la whitelist. Por defecto **22**
- **722** — knock, siempre abierto: es la vía de entrada. Limitado a 10 nuevas
  conexiones por minuto y por IP de origen

Los defaults son lo mínimo que sirve en cualquier servidor. Lo que sea de una
máquina concreta va en su `config.json` y no aquí — por ejemplo, en `help`:

```json
"publicPorts": [80, 443, 9443]
```

Un servicio que se use desde el navegador tiene que ir en `publicPorts`: no se
le puede pedir a quien lo usa que haga un knock por CLI antes. Su protección es
la del propio servicio, no la del firewall.

**Al actualizar desde una versión sin estos campos**, knock rellena los defaults
la primera vez que arranca. Si esa máquina tenía algún puerto extra abierto,
añádelo a `config.json` **antes** de desplegar, o se cerrará.

Un puerto que no esté en ninguna de las dos listas queda cerrado.

## Cómo trata iptables

Todas las reglas viven en una **cadena propia `KNOCK`**, enganchada al principio
de INPUT. `INPUT`, `OUTPUT` y `FORWARD` nunca se vacían y sus políticas no se
tocan, así que las reglas de cualquier otra cosa que corra en la máquina
sobreviven.

La cadena termina en `DROP`, o sea que deniega por defecto ella sola. Mientras
se reconstruye (al añadir una IP) la máquina falla **cerrada**, no abierta.

`knock open` **sí es destructivo, y a propósito**: vacía INPUT, OUTPUT y FORWARD,
pone las tres políticas en ACCEPT y borra la cadena KNOCK. Es la vía de escape
cuando te has quedado fuera o estás depurando, así que abre de verdad y no deja
nada a medias. Lo que no puede ser destructivo es el camino normal (añadir una
IP), y ese ya no toca nada fuera de su cadena.

## Archivos

- `/etc/knock/config.json` - configuración, puertos y lista de IPs
- `/etc/knock/host_key` - clave del servidor knock
- `/root/.ssh/authorized_keys` - claves públicas autorizadas para knock

Es **el mismo fichero que usa sshd**, a posta: quien puede entrar por SSH puede
knockear, y no hay nada que mantener sincronizado.

Las opciones de cada clave no se ignoran:

- `from="..."` — se comprueba contra la IP del cliente. Acepta CIDR, comodines y
  negación (`!`), como OpenSSH. knock no resuelve nombres, así que un patrón con
  hostname no casa.
- `expiry-time="..."` — una clave caducada no puede knockear.
- `command=`, `restrict`, `no-pty`, `no-port-forwarding`… — **se ignoran**, y es
  deliberado: limitan lo que puede hacer una *sesión*, y knock no abre ninguna.
  Comprueba una firma y escribe una regla de firewall.

## Cómo funciona

1. Cliente conecta al puerto 722 con SSH
2. Servidor verifica clave pública contra `/root/.ssh/authorized_keys`
3. Si OK, añade la IP del cliente a la cadena KNOCK
4. Cliente puede conectar por SSH normal (puerto 22)
