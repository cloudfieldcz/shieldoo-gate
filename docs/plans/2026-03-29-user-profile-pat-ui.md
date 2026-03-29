# User Profile & PAT Management UI — User menu, profil a správa API klíčů

## Popis

Přidání user menu do hlavního layoutu (kliknutelný email v headeru) s dropdown menu a nové stránky Profile, kde přihlášený uživatel vidí svůj profil a může generovat/spravovat Personal Access Tokeny (PAT) pro proxy endpointy.

### Proč

- Uživatel nemá žádnou vizuální indikaci, že je přihlášený — nevidí svůj email ani jméno
- PAT management backend existuje (POST/GET/DELETE `/api/v1/api-keys`), ale chybí UI
- Bez UI musí uživatel generovat tokeny přes curl/API — špatná DX
- Settings stránka obsahuje systémové věci (health, config) — per-user věci (profil, tokeny) tam nepatří

## Aktuální stav

### Backend (vyžaduje drobné opravy — owner-scoping)

| Endpoint | Metoda | Popis | Stav |
|----------|--------|-------|------|
| `/auth/userinfo` | GET | Vrací `{sub, email, name}` přihlášeného uživatele | OK |
| `/api/v1/api-keys` | POST | Vytvoří PAT, vrátí plaintext jednorázově | OK |
| `/api/v1/api-keys` | GET | Seznam PAT — **OPRAVIT: filtrovat per owner** | OPRAVA |
| `/api/v1/api-keys/{id}` | DELETE | Revokuje PAT — **OPRAVIT: owner check** | OPRAVA |

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
| Routing | 8 Route elementů pod Layout | +1 route `/profile` |

### Relevantní soubory

- `ui/src/components/Layout.tsx:1-57` — sidebar nav, žádný header, žádný user menu
- `ui/src/pages/Settings.tsx:1-133` — health + config + about, žádné PAT
- `ui/src/api/client.ts:1-116` — axios client, chybí apiKeys a user endpointy
- `ui/src/api/types.ts:1-107` — chybí APIKey a UserInfo typy
- `ui/src/App.tsx:1-41` — routes, chybí `/profile`

## Návrh řešení

### Architektura

Scope zahrnuje **frontend + drobné backend opravy** (owner-scoping na list/revoke).

```
Layout.tsx
├── Sidebar (beze změn)
├── Header (NOVÝ — top bar s user menu)
│   └── UserMenu component (veškerý stav UVNITŘ komponenty — ne v Layout)
│       ├── Email + avatar placeholder
│       ├── Dropdown: "Profile", "Logout" (Radix DropdownMenu pro a11y)
│       └── useQuery → GET /auth/userinfo (staleTime: Infinity)
└── <Outlet /> (beze změn)

Profile.tsx (NOVÁ stránka)
├── User info card (email, name, sub)
├── API Keys section (skrytá pokud GET /api-keys vrátí 404)
│   ├── Create button → POST /api/v1/api-keys → non-dismissible modal s tokenem
│   ├── Tabulka klíčů (name, created_at, last_used_at, status)
│   │   └── Revoked klíče zobrazeny greyed out s "Revoked" badge
│   └── Revoke button → confirmation dialog → DELETE /api/v1/api-keys/{id}
└── Usage instructions (snippety per ecosystem)
```

### Databázové změny

Přidat index na `owner_email` pro efektivní filtrování:

```sql
-- SQLite
CREATE INDEX IF NOT EXISTS idx_api_keys_owner_email ON api_keys(owner_email);

-- PostgreSQL
CREATE INDEX IF NOT EXISTS idx_api_keys_owner_email ON api_keys(owner_email);
```

### Změny v servisní vrstvě (backend opravy)

#### Owner-scoped list

Nová DB metoda `ListAPIKeysByOwner(ownerEmail string)`:
```go
func (db *GateDB) ListAPIKeysByOwner(ownerEmail string) ([]model.APIKey, error)
// SELECT ... FROM api_keys WHERE owner_email = ? ORDER BY created_at DESC
```

Handler `handleListAPIKeys` upraven — čte email z OIDC kontextu a volá `ListAPIKeysByOwner`.

#### Owner-scoped revoke

Handler `handleRevokeAPIKey` upraven — před revokací ověří, že `key.OwnerEmail == user.Email`.

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
  owner_email: string
  enabled: boolean
  created_at: string
  token: string    // backend JSON field je "token", NE "plaintext_key"
}
```

#### 2. Nové API funkce (`ui/src/api/client.ts`)

```typescript
// Druhá axios instance pro auth endpointy (bez /api/v1 prefix, S 401 interceptorem)
const authApi = axios.create({})
authApi.interceptors.response.use(
  (response) => response,
  (error) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      window.location.href = '/auth/login'
      return new Promise(() => {})
    }
    return Promise.reject(error)
  },
)

export const userApi = {
  me: () => authApi.get<UserInfo>('/auth/userinfo').then(r => r.data),
  logout: () => authApi.post('/auth/logout'),
}

export const apiKeysApi = {
  list: () => api.get<APIKey[]>('/api-keys').then(r => r.data),
  create: (name: string) => api.post<APIKeyCreateResponse>('/api-keys', { name }).then(r => r.data),
  revoke: (id: number) => api.delete(`/api-keys/${id}`),
}
```

#### 3. UserMenu komponent (`ui/src/components/UserMenu.tsx`)

- Použít `@radix-ui/react-dropdown-menu` pro a11y (keyboard nav, ARIA)
- Veškerý dropdown stav UVNITŘ komponenty (ne v Layout — prevence re-renderů)
- `useQuery({ queryKey: ['userinfo'], queryFn: userApi.me, staleTime: Infinity })` — data se nemění během session
- Loading state: skeleton placeholder v headeru
- Error state (non-401): fallback label "User", retry při další navigaci

#### 4. Layout změna (`ui/src/components/Layout.tsx`)

Přidání top header baru:
- Main content wrappnut do sloupcového flex containeru: header nahoře, `<Outlet />` pod ním
- Header obsahuje `<UserMenu />` vpravo
- Profile je **záměrně NE** v sidebar navigaci — je přístupný pouze přes UserMenu dropdown (sidebar = systémové features, profil = per-user)

#### 5. Nová stránka Profile (`ui/src/pages/Profile.tsx`)

Sekce:
- **User info** — email, jméno (read-only)
- **API Keys** — tabulka + create + revoke
  - `useQuery({ queryKey: ['api-keys'], queryFn: apiKeysApi.list, staleTime: 2 * 60 * 1000 })` — delší staleTime, data se mění jen explicitními akcemi
  - Po create/revoke: `queryClient.invalidateQueries({ queryKey: ['api-keys'] })` pro okamžitý refresh
  - Pokud GET vrátí 404 → sekce skrytá s info "API key management is not enabled in this deployment"
  - Revoked klíče zobrazeny greyed out s "Revoked" badge (audit trail)
- **Create flow:**
  - Input pro název (required, trimmed, 1-100 znaků, inline validace)
  - POST → non-dismissible modal (Radix Dialog) s tokenem
  - Modal nelze zavřít Escape ani klikem mimo — jen explicitní "Done" tlačítko
  - Varování: "Make sure you have copied the token. You will not be able to see it again."
  - Po zavření modalu: vyčistit token ze stavu
- **Revoke flow:**
  - Confirmation dialog: "Are you sure you want to revoke '{name}'? This action cannot be undone. Any systems using this token will lose access immediately."
- **Usage instructions** — copy-paste snippety per ecosystem:
  ```
  # PyPI
  pip install --index-url http://<email>:$SGW_TOKEN@<host>:5010/simple/ <package>

  # npm
  npm config set //<host>:4873/:_authToken $SGW_TOKEN

  # Docker
  docker login <host>:5002 -u <email> -p $SGW_TOKEN

  # NuGet
  dotnet nuget add source http://<host>:5001/v3/index.json -n shieldoo -u <email> -p $SGW_TOKEN

  # Go modules
  GONOSUMCHECK=<host>:8087/* GOPROXY=http://<email>:$SGW_TOKEN@<host>:8087 go get <module>

  # RubyGems
  gem sources --add http://<email>:$SGW_TOKEN@<host>:8086/
  ```
  Doporučení: používat env variable `$SGW_TOKEN` místo inline tokenu (bezpečnější — neloguje se do shell history).

#### 6. Route registrace (`ui/src/App.tsx`)

Přidání `<Route path="/profile" element={<Profile />} />`.

### Konfigurace

N/A — žádné nové config hodnoty.

## Dotčené soubory

### Nové soubory
- `ui/src/pages/Profile.tsx` — profil + PAT management stránka
- `ui/src/components/UserMenu.tsx` — user menu dropdown komponent
- `internal/config/migrations/sqlite/010_api_keys_owner_index.sql` — index na owner_email
- `internal/config/migrations/postgres/010_api_keys_owner_index.sql` — index na owner_email

### Upravené soubory
- `ui/src/api/types.ts:107` — přidání `UserInfo`, `APIKey`, `APIKeyCreateResponse` typů
- `ui/src/api/client.ts:116` — přidání `authApi` instance, `userApi` a `apiKeysApi`
- `ui/src/components/Layout.tsx:13-55` — přidání header baru s UserMenu
- `ui/src/App.tsx:1-41` — import Profile, přidání `/profile` route
- `internal/config/db_apikeys.go:36-44` — nová metoda `ListAPIKeysByOwner`
- `internal/api/apikeys.go:88-115` — owner-scoping na list a revoke handlery
- `ui/package.json` — přidání `@radix-ui/react-dropdown-menu`, `@radix-ui/react-dialog`

### Soubory BEZ změn (důležité)
- `internal/auth/handlers.go` — userinfo endpoint je hotový
- `internal/api/server.go` — routes jsou registrované
- `internal/model/apikey.go` — model se nemění
- `ui/src/pages/Settings.tsx` — zůstává pro systémové nastavení
- `ui/src/pages/Dashboard.tsx` — beze změn

## Implementační fáze

### Fáze 1: Backend opravy (owner-scoping)

Prerequisite pro frontend — bez tohoto by UI ukazoval cizí klíče.

- [ ] Přidat migration `010_api_keys_owner_index.sql` (SQLite + PostgreSQL)
- [ ] Přidat `ListAPIKeysByOwner` do `db_apikeys.go`
- [ ] Upravit `handleListAPIKeys` — filtrovat per owner
- [ ] Upravit `handleRevokeAPIKey` — owner check
- [ ] Unit testy pro owner-scoping

### Fáze 2: Frontend — User Profile & PAT UI

- [ ] Přidat TypeScript typy do `types.ts`
- [ ] Přidat `authApi` instanci, `userApi` a `apiKeysApi` do `client.ts`
- [ ] Nainstalovat `@radix-ui/react-dropdown-menu` a `@radix-ui/react-dialog`
- [ ] Vytvořit `UserMenu.tsx` komponent
- [ ] Upravit `Layout.tsx` — přidat header s UserMenu
- [ ] Vytvořit `Profile.tsx` stránku s PAT management
- [ ] Přidat `/profile` route do `App.tsx`
- [ ] Aktualizovat dokumentaci v `docs/`

## Rizika a mitigace

| Riziko | Dopad | Pravděpodobnost | Mitigace |
|--------|-------|-----------------|----------|
| Plaintext token zobrazen v UI a uživatel ho ztratí | Střední — musí vytvořit nový | Střední | Non-dismissible modal s "Done" tlačítkem + varování |
| UserMenu dropdown se překrývá se sidebar | Nízký | Nízká | Z-index management, Radix handles positioning |
| `/auth/userinfo` vrátí 401 po expiraci session | Střední | Střední | `authApi` instance s 401 interceptorem → redirect na login |
| Uživatel omylem revokuje token používaný v CI/CD | Vysoký | Nízká | Confirmation dialog s jasným varováním |
| Token v clipboard/shell history | Nízký | Střední | Usage instructions doporučují env variable místo inline |

## Testování

### Unit testy
- `TestListAPIKeys_FiltersByOwner` — ověří že user vidí jen své klíče
- `TestRevokeAPIKey_RejectsNonOwner` — ověří 403 pro cizí klíč

### Manuální testy
- [ ] Přihlásit se přes OIDC → ověřit že header zobrazuje email
- [ ] Kliknout na email → dropdown s "Profile" a "Logout"
- [ ] Keyboard navigace v dropdown (Tab, Enter, Escape)
- [ ] Přejít na Profile → vidět user info
- [ ] Vytvořit PAT → non-dismissible modal s tokenem, "Done" tlačítko
- [ ] Zkopírovat token, zavřít modal → token zmizí ze stavu
- [ ] Ověřit že plaintext token funguje: `curl -u me:TOKEN http://localhost:5010/simple/`
- [ ] Revokovat PAT → confirmation dialog → klíč greyed out s "Revoked" badge
- [ ] Ověřit že revokovaný token nefunguje
- [ ] Logout → redirect na login stránku
- [ ] Pokud proxy_auth vypnutý → API Keys sekce skrytá s info message

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
- Po zavření create modalu se token vyčistí z React stavu
- `apiKeysApi` endpointy jsou registrované jen když `proxy_auth.enabled=true` A `auth.enabled=true` — pokud proxy auth vypnutý, GET vrátí 404 a UI sekci skryje
- Profile je záměrně NE v sidebar navigaci — přístupný pouze přes UserMenu dropdown
- Pagination na api-keys není potřeba pro v1.1 — očekávaná kardinalita je nízká (< 100 klíčů per user)
- Usage instructions doporučují `$SGW_TOKEN` env variable místo inline tokenu v URL

## Cross-check review výsledky

Analýza prošla 4 paralelními reviews (BA, Dev, Security, Perf). Zapracované nálezy:

| Nález | Závažnost | Řešení |
|-------|-----------|--------|
| `plaintext_key` → `token` field name | Kritický | Opraven typ na `token` |
| ListAPIKeys vrací klíče všech uživatelů | Vysoký | Přidána Fáze 1 — backend owner-scoping |
| RevokeAPIKey bez owner check | Střední | Přidán owner check do Fáze 1 |
| `userApi.me()` bez 401 interceptoru | Střední | Nová `authApi` instance s interceptorem |
| Chybí confirmation dialog pro revoke | Střední | Přidán requirement |
| Token modal dismissible | Střední | Non-dismissible modal, explicitní "Done" |
| userinfo staleTime 30s zbytečně krátký | Střední | `staleTime: Infinity` |
| Chybí query invalidation po mutacích | Střední | Přidán requirement |
| CSRF na logout/revoke | Nízký | Zamítnuto — SameSite=Lax + non-simple methods dostatečné |

## Reference

- Backend plan: `docs/plans/2026-03-29-v1.1-proxy-api-key-auth.md`
- OIDC auth plan: `docs/plans/2026-03-28-v1.1-05-oidc-auth.md`
- OpenAPI spec: `docs/api/openapi.yaml:460-618` (api-keys schema)
- Aktuální Layout: `ui/src/components/Layout.tsx`
- Aktuální Settings: `ui/src/pages/Settings.tsx`
