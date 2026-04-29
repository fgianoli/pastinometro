# Pastinometro

Guida critica alle pastine di riso (e dolci tradizionali padovani) — webapp self-hosted.

Stack: **FastAPI + SQLite + Docker**, frontend HTML statico in `pastinometro.html`.
Singolo container, nessun servizio esterno. Pensato per girare dietro Nginx Proxy Manager.

---

## Avvio rapido (test locale)

Per provarlo sul tuo PC senza NPM:

```bash
cp .env.example .env
# in .env: COOKIE_SECURE=false   (perche' http://localhost non e' HTTPS)
# in docker-compose.yml: decommenta la sezione "ports:" sotto pastinometro
docker compose up -d --build
```

App su `http://localhost:8000`. Password admin: nei log (`docker compose logs pastinometro`) o in `data/admin_password.txt`.

---

## Deploy in produzione

Il setup parte dal presupposto che sul server gira gia' Nginx Proxy Manager
connesso a una rete docker condivisa (`docker-stack_proxy` nel mio caso).
Il container `pastinometro` non espone porte sull'host: e' raggiungibile
solo via la rete docker da NPM, che si occupa di HTTPS e dominio.

### 1. Sul server

```bash
git clone https://github.com/fgianoli/pastinometro.git
cd pastinometro
cp .env.example .env
nano .env
```

In `.env` lascia `COOKIE_SECURE=true` (NPM termina HTTPS) e:
- imposta `ADMIN_PASSWORD=<la-tua-password>` per sceglierla tu, oppure
- lascialo vuoto: viene generata automaticamente al primo avvio.

```bash
docker compose up -d --build
docker compose logs pastinometro --tail=30
```

Se hai lasciato `ADMIN_PASSWORD` vuoto, vedi un blocco `ADMIN ACCOUNT CREATED`
con la password. La trovi anche in `data/admin_password.txt`.

> Se la rete docker NPM nel tuo setup ha un nome diverso da `docker-stack_proxy`,
> modifica `docker-compose.yml`:
> ```yaml
> networks:
>   proxy:
>     external: true
>     name: <NOME-DELLA-TUA-RETE>
> ```
> Per vedere la lista: `docker network ls`.

### 2. DNS

Crea un record A (o CNAME) per `pastinometro.federicogianoli.eu` che punta
all'IP del server. Aspetta la propagazione prima del passo successivo
(altrimenti Let's Encrypt fallisce la validazione).

### 3. In Nginx Proxy Manager

**Hosts → Proxy Hosts → Add Proxy Host**

Tab **Details**:
- Domain Names: `pastinometro.federicogianoli.eu`
- Scheme: `http`
- Forward Hostname / IP: `pastinometro`
- Forward Port: `8000`
- Block Common Exploits: ON
- Websockets Support: OFF (non necessario)

Tab **SSL**:
- SSL Certificate: **Request a new SSL Certificate**
- Force SSL: ON
- HTTP/2 Support: ON
- HSTS Enabled: ON
- Use a DNS Challenge: OFF (HTTP-01 va bene)
- Email: `gianoli.federico@gmail.com`
- I Agree: ON
- **Save**

Apri `https://pastinometro.federicogianoli.eu` e fai login con `admin` +
password (quella che hai impostato o generata).

### 4. Aggiornamenti futuri

```bash
cd pastinometro
git pull
docker compose up -d --build
```

Il volume `./data` non viene toccato: DB, password admin, recensioni e foto
restano. Solo l'immagine viene ricostruita.

---

## File

| file | ruolo |
|---|---|
| `app.py` | FastAPI: auth + KV store + serve dell'HTML |
| `pastinometro.html` | frontend (mappa, recensioni, login) |
| `requirements.txt` | dipendenze Python |
| `Dockerfile` | build immagine |
| `docker-compose.yml` | servizio singolo |
| `.env.example` | template config |
| `static/` | manifest, icone PWA |
| `data/` | volume persistente: DB SQLite, foto utenti, snapshot OSM, password admin |

---

## API

Tutte le rotte sotto `/api`. Cookie di sessione `psm_session` (httpOnly, SameSite=Lax).

**Auth**
- `POST /api/auth/register` `{username, password, email?}` → setta cookie (rate limit: 5/h/IP)
- `POST /api/auth/login` `{username, password}` → setta cookie (rate limit: 10/min/IP)
- `POST /api/auth/logout`
- `GET  /api/auth/me` → `{user: {id, username, email, isAdmin} | null}`
- `POST /api/auth/change-password` `{current_password, new_password}` (richiede login)
- `POST /api/auth/forgot` `{email}` → 200 sempre. Manda link via SMTP se configurato (5/10min/IP)
- `POST /api/auth/reset` `{token, new_password}` → reset con token monouso (10/10min/IP)
- `GET  /api/auth/email-config` → `{enabled: bool}` per il frontend

**Foto**
- `POST /api/photos` (multipart, 4 MB max, 30/min/IP) → `{url: "/photos/<sha256>.jpg"}`
- `GET /photos/<file>` → file foto (servito da FastAPI StaticFiles)

**Admin**
- `POST /api/admin/osm-reimport` (admin) → rilancia Overpass, salva snapshot
- `GET /api/osm-places` → snapshot OSM corrente (`{places: [...], ts}`)

**KV** (replica `window.storage`)
- `GET    /api/kv?key=…&shared=true|false` → `{value, updatedAt}` o 404
- `PUT    /api/kv?key=…&shared=…` body `{value: "<json string>"}`
- `DELETE /api/kv?key=…&shared=…`
- `GET    /api/kv/list?prefix=…&shared=…` → `{keys: […]}`
- `GET    /api/kv/scan?prefix=…&shared=…` → `{items: [{key, value}]}` (single-call, evita N+1)

`shared=true`: dati condivisi visibili a tutti (recensioni, luoghi user-added, pastine custom, disponibilità).
`shared=false`: dati privati per utente loggato.

Tutte le mutazioni richiedono autenticazione. Le letture `shared=true` sono pubbliche.

OpenAPI auto-generata su `/api/docs`.

---

## Schema dati (chiavi KV)

| pattern | scope | contenuto |
|---|---|---|
| `review:<placeId>:<reviewId>` | shared | `{id, placeId, pastryKey, userId, userName, crits, score, text, photos[], ts}` |
| `place:<id>` | shared | luogo aggiunto da utente |
| `pastry:<key>` | shared | pastina custom |
| `avail:<placeId>:<pastryKey>` | shared | segnalazione disponibilità (last-write-wins) |

---

## SMTP / reset password

Per abilitare il flusso "password dimenticata" via email, configura le
variabili `SMTP_*` e `MAIL_FROM` nel `.env`. Il `.env.example` ha esempi
per Gmail, Resend e SMTP di provider hosting.

Se le variabili sono vuote, il link "password dimenticata?" non compare
nel modale di login e l'endpoint `/api/auth/forgot` risponde 503.

`BASE_URL` viene usato per costruire i link assoluti nelle email — se
non lo imposti, viene usato l'host della richiesta (di solito OK dietro NPM).

## Re-import OSM

Quando vuoi aggiornare il dataset dei locali da OpenStreetMap (apertura
nuovi locali, chiusure, correzioni), entra come admin e clicca **🔄 OSM**
nella userbar. Il backend rilancia la query Overpass e salva uno snapshot
JSON in `data/osm_places.json`. Il frontend al prossimo refresh prende
quello invece dei dati embeddati nell'HTML.

Override utente (categoria corretta, status chiuso/trasferito), recensioni
e luoghi user-added **non vengono toccati** dal reimport.

## Limitazioni note (MVP)

- Foto piu' vecchie del 2026-04-29 sono ancora come dataURL base64 dentro
  i record review:* nel KV. Le nuove vanno su filesystem in `data/photos/`.
  Entrambi i formati funzionano nelle recensioni; nessuna migration retroattiva.
- DELETE su risorse shared: enforcement basato su `owner_id` (impostato al
  primo PUT). Risorse antecedenti la migration hanno `owner_id = NULL` e
  sono cancellabili da chiunque (legacy). Cascade per place/pastry owner.
- SQLite va benissimo fino a qualche migliaio di utenti / decine di migliaia
  di recensioni. Oltre conviene migrare a Postgres (lo schema KV è
  trasferibile 1:1).

---

## Backup

Tutto sta in `data/`:

```bash
docker compose stop pastinometro
tar czf pastinometro-backup-$(date +%F).tgz data/
docker compose start pastinometro
```

`data/pastinometro.db` è il DB. È in modalità WAL: per backup a caldo
sicuro usa `sqlite3 data/pastinometro.db ".backup data/backup.db"`.

---

## Reset admin password

```bash
docker compose exec pastinometro python -c "
import bcrypt, sqlite3, os
pw = 'NUOVA_PASSWORD_QUI'
h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
c = sqlite3.connect('/data/pastinometro.db')
c.execute('UPDATE users SET password_hash=? WHERE username=?', (h, 'admin'))
c.commit(); c.close()
print('ok')
"
```
