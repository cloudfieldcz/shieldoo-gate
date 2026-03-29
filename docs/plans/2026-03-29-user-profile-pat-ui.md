# User Profile & PAT Management UI — User menu, profil a správa API klíčů

## Popis

Přidání user menu do hlavního layoutu (kliknutelný email v headeru) s dropdown menu a nové stránky Profile, kde přihlášený uživatel vidí svůj profil a může generovat/spravovat Personal Access Tokeny (PAT) pro proxy endpointy.

### Proč

- Uživatel nemá žádnou vizuální indikaci, že je přihlášený — nevidí svůj email ani jméno
- PAT management backend existuje (POST/GET/DELETE `/api/v1/api-keys`), ale chybí UI
- Bez UI musí uživatel generovat tokeny přes curl/API — špatná DX
- Settings stránka obsahuje systémové věci (health, config) — per-user věci (profil, tokeny) tam nepatří

## Aktuální stav

### Backend (hotovo, není třeba měnit)

| Endpoint | Metoda | Popis |
|----------|--------|-------|
| `/auth/userinfo` | GET | Vrací `{sub, email, name}` přihlášeného uživatele |
| `/api/v1/api-keys` | POST | Vytvoří PAT, vrátí plaintext jednorázově |
| `/api/v1/api-keys` | GET | Seznam všech PAT (bez hash/plaintext) |
| `/api/v1/api-keys/{id}` | DELETE | Revokuje PAT (soft-disable) |

Backend handlery: `internal/api/apikeys.go:40-129`
Model: `internal/model/apikey.go:1-16`
DB operace: `internal/config/db_apikeys.go`
Auth userinfo: `internal/auth/handlers.go:232-242`
Route registrace: `internal/api/server.go:138-148`

### Frontend (aktuální stav)

| Aspekt | Současný stav | Navrhovaný stav |
|--------|--------------|-----------------|
| User info v UI | Žádný — uživatel nevidí kdo je přihlášený | Email v headeru + user dropdown menu |
| PAT management | Neexistuje — jen backend API | Profile stránka s tabulkou PAT + create/revoke |
| Logout | Neexistuje v UI — jen POST endpoint | Položka v user dropdown menu |
| API client | Nemá `apiKeysApi` ani `userApi` | Oba přidány v `client.ts` |
| Types | Nemá `APIKey` ani `UserInfo` typy | Přidány v `types.ts` |
| Routing | 7 routes pod Layout | +1 route `/profile` |

### Relevantní soubory

- `ui/src/components/Layout.tsx:1-57` — sidebar nav, žádný header, žádný user menu
- `ui/src/pages/Settings.tsx:1-133` — health + config + about, žádné PAT
- `ui/src/api/client.ts:1-116` — axios client, chybí apiKeys a user endpointy
- `ui/src/api/types.ts:1-107` — chybí APIKey a UserInfo typy
- `ui/src/App.tsx:1-41` — routes, chybí `/profile`

## Návrh řešení

### Architektura

Celý scope je **frontend-only** — backend je hotový a není třeba ho měnit.

```
Layout.tsx
├── Sidebar (beze změn)
├── Header (NOVÝ — top bar s user menu)
│   └── UserMenu component
│       ├── Email + avatar placeholder
│       ├── Dropdown: "Profile", "Logout"
│       └── useQuery → GET /auth/userinfo
└── <Outlet /> (beze změn)

Profile.tsx (NOVÁ stránka)
├── User info card (email, name, sub)
├── API Keys section
│   ├── Create button → POST /api/v1/api-keys → modal s plaintext tokenem
│   ├── Tabulka existujících klíčů (name, created_at, last_used_at, status)
│   └── Revoke button → DELETE /api/v1/api-keys/{id}
└── Usage instructions (jak token použít s pip/npm/docker)
```

### Databázové změny

N/A — schema `api_keys` tabulky již existuje.

### Změny v servisní vrstvě

N/A — backend API je kompletní.

### Změny v UI

#### 1. Nové TypeScript typy (`ui/src/api/types.ts`)

```typescript
export interface UserInfo {
  sub: string
  email: string
  name: string
}

export interface APIKey {
  id: number
  name: string
  owner_email: string
  enabled: boolean
  created_at: string
  last_used_at?: string
}

export interface APIKeyCreateResponse {
  id: number
  name: string
  plaintext_key: string
}
```

#### 2. Nové API funkce (`ui/src/api/client.ts`)

```typescript
export const userApi = {
  me: () => axios.get<UserInfo>('/auth/userinfo').then(r => r.data),
}

export const apiKeysApi = {
  list: () => api.get<APIKey[]>('/api-keys').then(r => r.data),
  create: (name: string) => api.post<APIKeyCreateResponse>('/api-keys', { name }).then(r => r.data),
  revoke: (id: number) => api.delete(`/api-keys/${id}`),
}
```

Poznámka: `userApi.me()` používá base axios (ne `api` instanci s `/api/v1` prefix), protože endpoint je `/auth/userinfo`.

#### 3. Layout změna (`ui/src/components/Layout.tsx`)

Přidání top header baru s user menu:
- `useQuery(['userinfo'], userApi.me)` — načte user info
- Zobrazí email vpravo nahoře
- Click → dropdown s "Profile" a "Logout"
- Logout → POST `/auth/logout` → redirect na `/auth/login`

#### 4. Nová stránka Profile (`ui/src/pages/Profile.tsx`)

Sekce:
- **User info** — email, jméno (read-only)
- **API Keys** — tabulka + create + revoke
- **Create flow** — input pro název → POST → modal s plaintext tokenem (kopírovatelný, zobrazený jednou)
- **Usage instructions** — jak použít token s `pip install --index-url http://user:TOKEN@host:5010/simple/`

#### 5. Route registrace (`ui/src/App.tsx`)

Přidání `<Route path="/profile" element={<Profile />} />`.

### Konfigurace

N/A — žádné nové config hodnoty.

## Dotčené soubory

### Nové soubory
- `ui/src/pages/Profile.tsx` — profil + PAT management stránka
- `ui/src/components/UserMenu.tsx` — user menu dropdown komponent

### Upravené soubory
- `ui/src/api/types.ts:107` — přidání `UserInfo`, `APIKey`, `APIKeyCreateResponse` typů
- `ui/src/api/client.ts:116` — přidání `userApi` a `apiKeysApi`
- `ui/src/components/Layout.tsx:13-55` — přidání header baru s UserMenu
- `ui/src/App.tsx:1-41` — import Profile, přidání `/profile` route

### Soubory BEZ změn (důležité)
- `internal/api/apikeys.go` — backend je hotový
- `internal/auth/handlers.go` — userinfo endpoint je hotový
- `internal/api/server.go` — routes jsou registrované
- `ui/src/pages/Settings.tsx` — zůstává pro systémové nastavení
- `ui/src/pages/Dashboard.tsx` — beze změn

## Implementační fáze

Celý scope je jedna koherentní fáze — všechny části jsou provázané a nemá smysl je dělit.

### Fáze 1: User Profile & PAT UI

Vše se implementuje najednou, protože:
- UserMenu potřebuje `userApi` → potřebuje typy
- Profile potřebuje `apiKeysApi` → potřebuje typy
- Route potřebuje Profile komponent
- Testovat lze až když je vše propojené

- [ ] Přidat TypeScript typy do `types.ts`
- [ ] Přidat `userApi` a `apiKeysApi` do `client.ts`
- [ ] Vytvořit `UserMenu.tsx` komponent
- [ ] Upravit `Layout.tsx` — přidat header s UserMenu
- [ ] Vytvořit `Profile.tsx` stránku s PAT management
- [ ] Přidat `/profile` route do `App.tsx`
- [ ] Aktualizovat dokumentaci v `docs/`

## Rizika a mitigace

| Riziko | Dopad | Pravděpodobnost | Mitigace |
|--------|-------|-----------------|----------|
| Plaintext token zobrazen v UI a uživatel ho ztratí | Střední — musí vytvořit nový | Střední | Jasný UX: "Tento token se zobrazí pouze jednou. Zkopírujte si ho nyní." |
| UserMenu dropdown se překrývá se sidebar | Nízký | Nízká | Z-index management, positioning relative to header |
| `/auth/userinfo` vrátí 401 po expiraci session | Střední | Střední | Axios interceptor již handluje 401 → redirect na login |

## Testování

### Unit testy
N/A — jedná se o čistě UI práci, backend testy již existují v `internal/api/apikeys_test.go`.

### Manuální testy
- [ ] Přihlásit se přes OIDC → ověřit že header zobrazuje email
- [ ] Kliknout na email → dropdown s "Profile" a "Logout"
- [ ] Přejít na Profile → vidět user info
- [ ] Vytvořit PAT → zobrazí se plaintext token, lze zkopírovat
- [ ] Ověřit že plaintext token funguje: `curl -u me:TOKEN http://localhost:5010/simple/`
- [ ] Revokovat PAT → zmizí z tabulky (nebo se zobrazí jako disabled)
- [ ] Logout → redirect na login stránku

### Verifikace
```bash
# Build UI
cd ui && npm run build

# Build Go (ověří že se nic nerozbilo)
go build ./...

# Spustit testy
make test
```

## Poznámky

- Plaintext token se zobrazuje **jednou** při vytvoření — backend ho neukládá, nelze ho znovu získat
- `apiKeysApi` endpointy jsou registrované jen když `proxy_auth.enabled=true` A `auth.enabled=true` — pokud je proxy auth vypnutý, Profile stránka by měla sekci API Keys skrýt nebo zobrazit info message
- UserMenu by neměl volat `/auth/userinfo` pokud auth není enabled — ale v praxi se tam uživatel bez auth nedostane (serveSPA redirectuje)

## Reference

- Backend plan: `docs/plans/2026-03-29-v1.1-proxy-api-key-auth.md`
- OIDC auth plan: `docs/plans/2026-03-28-v1.1-05-oidc-auth.md`
- OpenAPI spec: `docs/api/openapi.yaml:460-618` (api-keys schema)
- Aktuální Layout: `ui/src/components/Layout.tsx`
- Aktuální Settings: `ui/src/pages/Settings.tsx`
