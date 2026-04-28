# Pastinometro

Guida critica alle pastine di riso (e dolci tradizionali padovani) — webapp self-hosted.

Stack: **FastAPI + SQLite + Docker**, frontend HTML statico in `pastinometro.html`.
Singolo container, nessun servizio esterno. Pensato per girare dietro Nginx Proxy Manager.

---

## Avvio rapido (locale)

```bash
cp .env.example .env
# per test su http://localhost (senza HTTPS) imposta:
#   COOKIE_SECURE=false
docker compose up -d --build
```

App raggiungibile su `http://localhost:8000`.

Al primo avvio viene creato l'utente admin. Se non hai impostato
`ADMIN_PASSWORD` nel `.env`, la password è generata casualmente: la trovi nei
log (`docker compose logs pastinometro`) e in `data/admin_password.txt`.

---

## Deploy in produzione (server con NPM)

1. Carica la cartella sul server (`scp`/`rsync`/`git pull`).
2. Crea il `.env` partendo da `.env.example`:
   - `COOKIE_SECURE=true` (NPM termina HTTPS)
   - `ADMIN_PASSWORD=<la-tua-password-sicura>` se la vuoi scegliere tu
   - altrimenti lascialo vuoto e leggi la password generata da `data/admin_password.txt`
3. `docker compose up -d --build`
4. In Nginx Proxy Manager: nuova **Proxy Host**
   - Domain: `pastinometro.studiogis.eu`
   - Forward Hostname: `pastinometro` (se NPM è sulla stessa rete docker) oppure l'IP host con porta `8000`
   - SSL: Let's Encrypt, **Force SSL** + **HTTP/2** + **HSTS**
   - Websockets: non necessari
5. Apri `https://pastinometro.studiogis.eu`, fai login con `admin` + password.

> Se NPM e il container non sono sulla stessa rete docker, aggiungili a una
> rete comune o usa `forward host: <IP host>` + porta esposta.

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
| `data/` | volume persistente (DB SQLite + password admin) |

---

## API

Tutte le rotte sotto `/api`. Cookie di sessione `psm_session` (httpOnly, SameSite=Lax).

**Auth**
- `POST /api/auth/register` `{username, password, email?}` → setta cookie
- `POST /api/auth/login` `{username, password}` → setta cookie
- `POST /api/auth/logout`
- `GET  /api/auth/me` → `{user: {id, username, email, isAdmin} | null}`

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

## Limitazioni note (MVP)

- Le foto sono base64 dentro la recensione (max 6 MB per recensione). Per
  scalare oltre poche centinaia di recensioni con foto, sposta su object
  storage (MinIO/S3) e tieni nel DB solo l'URL.
- Nessuna autorizzazione fine sulle DELETE shared: il frontend mostra il
  pulsante elimina solo all'autore, ma l'endpoint accetta da qualsiasi utente
  loggato. Adatto a una community ristretta; da rinforzare per app pubblica.
- Niente reset password / email magic-link: l'admin può rigenerare manualmente
  un hash bcrypt dentro la tabella `users`.
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
