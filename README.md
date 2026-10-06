# knock

Port knocking firewall. Los puertos protegidos (SSH y demás) están bloqueados a
todo el mundo excepto a las IPs autorizadas. Para añadir tu IP haces "knock",
autenticándote con tu clave SSH contra el puerto 722.

## Instalación

```bash
knock deploy user@servidor
```

Se lanza desde un clon de este repo y necesita Go: compila knock para el
servidor. Fuera del código fuente avisa y no toca nada. Los binarios de las
releases sirven para knockear desde mac, Windows o Linux.

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
knock servidor out  # Quita tu IP: lo contrario de un knock
```

La clave del servidor se fija en el primer knock (TOFU) y se guarda en
`~/.knock/known_hosts.json`. Si cambia, el knock falla — borra la entrada si has
reinstalado el servidor.

`out` no lleva argumento **a propósito**: solo puede quitar la IP desde la que
llamas, así que no puede tocar el acceso de nadie más. Tu sesión SSH abierta no
se corta (la cadena acepta `ESTABLISHED` primero); afecta a conexiones nuevas.

## Qué escucha el puerto 722

El 722 está abierto a todo internet, así que hace **una cosa**: te abre y te
cierra. Nada más.

Son las dos únicas operaciones que llegan por la red, y las dos están limitadas
a la IP de quien llama: el knock no lleva IP y `out` no lleva argumento, así que
ninguna puede tocar el acceso de nadie más. No hay que razonar sobre qué comando
es seguro exponer, porque no hay más comandos.

La comprobación está **en el servidor** (`runRemoteCommand`, `server.go`), no en
el cliente, y no es una tabla con un flag: es comparar con `out`.

## Uso (servidor)

Administrar la máquina se hace **en la máquina**, entrando por SSH:

```bash
knock status        # Ver estado, puertos públicos y protegidos
knock list          # Listar IPs en whitelist
knock add 1.2.3.4   # Añadir IP manualmente
knock remove 1.2.3.4
knock clear         # Eliminar todas las IPs
knock open          # Desactivar el firewall entero (vía de escape)
knock close         # Activar el firewall
```

`knock -h` lo resume. `remove <ip>` se niega a vaciar la whitelist con el
firewall activo: quita el acceso a otro, que no ha pedido nada. `out` no lleva
ese freno — te quitas tú, a sabiendas, y knockeas otra vez cuando quieras.

## Puertos

Configurables en `/etc/knock/config.json`:

- `publicPorts` — abiertos a todo el mundo. Por defecto **80, 443**
- `protectedPorts` — solo desde IPs de la whitelist. Por defecto **22**
- **722** — knock, siempre abierto: es la vía de entrada. Limitado a 10 nuevas
  conexiones por minuto y 2 a la vez por origen (en IPv6, por /64), y cada
  conexión se corta a los 10 s. Así nadie puede ocupar el puerto abriendo
  conexiones sin enviar nada y dejarte sin knock

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

La cadena termina en `DROP`, o sea que deniega por defecto ella sola. Se carga
entera en una sola transacción (`iptables-restore --noflush`): nunca queda
vacía ni sin su `DROP` final, ni siquiera un instante. Si algo falla, se queda
la cadena anterior.

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

Un knock y un comando remoto son la misma conexión, y se distinguen por el
nombre de usuario con el que autentica el cliente (`knock` o `command`). El
servidor tiene que saber cuál de los dos es **antes** de actuar: un knock
whitelistea al que llama nada más verlo, y un comando no debe hacerlo nunca — si
no, `knock <host> out` se desharía a sí mismo.
