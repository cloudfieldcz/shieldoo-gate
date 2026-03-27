# Audit Log API Endpoint — Doplnění chybějícího endpointu

## Popis

UI stránka Audit Log (`ui/src/pages/AuditLog.tsx`) volá `GET /api/v1/audit`, ale tento endpoint neexistuje na backendu. Požadavek propadne přes SPA wildcard handler a vrátí HTML místo JSON, což způsobí chybu "Failed to load audit log. Is the API server running?".

### Proč

- Audit log tabulka existuje v DB schématu (sekce 4.6 specifikace)
- Adaptéry do ní zapisují přes `WriteAuditLog()` (`internal/adapter/base.go:59`)
- UI stránka i API klient jsou implementované (`ui/src/pages/AuditLog.tsx`, `ui/src/api/client.ts:41-48`)
- Chybí pouze backend handler a registrace route
- Endpoint nebyl zahrnutý do sekce 10 specifikace (mezera v dokumentaci)

## Aktuální stav

| Aspekt | Současný stav | Navrhovaný stav |
|--------|--------------|-----------------|
| Route `/api/v1/audit` | Neexistuje — propadne do SPA fallback | Registrovaná GET route s handlerem |
| Event type konstanty (Go) | `SERVED`, `BLOCKED`, `QUARANTINED`, `RELEASED`, `SCANNED` (`internal/model/audit.go:8-12`) | Beze změny — DB i adaptéry používají tyto hodnoty |
| Event type konstanty (UI) | `ARTIFACT_SERVED`, `ARTIFACT_BLOCKED` atd. (`ui/src/pages/AuditLog.tsx:8-13`) | Opravit na `SERVED`, `BLOCKED` atd. — srovnat s Go modelem |
| Pagination response field (Go) | `json:"items"` (`internal/api/artifacts.go:26`) | Změnit na `json:"data"` — srovnat s UI `PaginatedResponse<T>` |
| Pagination response field (UI) | `data: T[]` (`ui/src/api/types.ts:63`) | Beze změny |
| OpenAPI spec | Nemá `/api/v1/audit` endpoint | Doplnit |
| Specifikace (initial-analyse.md) | Sekce 10 nemá audit endpoint | Doplnit |

### Relevantní code paths

- **UI stránka:** `ui/src/pages/AuditLog.tsx` — celý soubor, volá `auditApi.list()`
- **UI API klient:** `ui/src/api/client.ts:41-48` — `auditApi.list()` → `GET /api/v1/audit`
- **UI typy:** `ui/src/api/types.ts:34-42` — `AuditEntry` interface, `PaginatedResponse<T>` (řádek 62-67)
- **Go model:** `internal/model/audit.go` — `AuditEntry` struct, `EventType` konstanty
- **Go router:** `internal/api/server.go:47-66` — chybí audit route
- **Go pagination:** `internal/api/artifacts.go:25-30` — `paginatedResponse` struct s `json:"items"`
- **Zápis audit logu:** `internal/adapter/base.go:59-78` — `WriteAuditLog()` funkce
- **Existující pattern:** `internal/api/stats.go:98-127` — `handleStatsBlocked` čte z `audit_log` tabulky

### Data flow

```
UI (AuditLog.tsx)
  → auditApi.list(page, perPage, eventType)
    → GET /api/v1/audit?page=1&per_page=50&event_type=SERVED
      → [CHYBÍ handler]
      → propadne do serveSPA → vrátí HTML
    → Axios parse fail → query.isError → "Failed to load audit log"
```

## Návrh řešení

### Architektura

Nový handler `handleListAudit` v novém souboru `internal/api/audit.go`, registrovaný v routeru. Následuje existující vzor z `handleListArtifacts` (stránkování) a `handleStatsBlocked` (čtení z `audit_log`).

### Databázové změny

Žádné — tabulka `audit_log` již existuje.

### Změny v servisní vrstvě

Nový handler `handleListAudit` na `*Server`:

```go
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request)
```

Query parametry: `page`, `per_page`, `event_type` (volitelný filtr).

SQL: `SELECT ... FROM audit_log [WHERE event_type = ?] ORDER BY ts DESC LIMIT ? OFFSET ?` + `SELECT COUNT(*)` pro total.

### Změny v UI

Opravit event type konstanty v `AuditLog.tsx` — odstranit prefix `ARTIFACT_`.

### Konfigurace

Žádné změny.

## Dotčené soubory

### Nové soubory
- `internal/api/audit.go` — handler `handleListAudit`
- `internal/api/audit_test.go` — testy

### Upravené soubory
- `internal/api/server.go:47-66` — přidat `r.Get("/audit", s.handleListAudit)`
- `internal/api/artifacts.go:25-30` — změnit `paginatedResponse.Items` z `json:"items"` na `json:"data"`
- `ui/src/pages/AuditLog.tsx:6-13` — opravit event type konstanty (odstranit `ARTIFACT_` prefix)
- `docs/api/openapi.yaml` — přidat `/api/v1/audit` endpoint + `AuditEntry` schema + `AuditPage` schema, opravit `ArtifactPage.items` na `data`
- `docs/initial-analyse.md:779-799` — přidat audit endpoint do sekce 10 REST API

### Soubory BEZ změn
- `internal/model/audit.go` — model je správný, UI se přizpůsobí
- `internal/adapter/base.go` — `WriteAuditLog` je správný
- `ui/src/api/client.ts` — API volání je správné
- `ui/src/api/types.ts` — `AuditEntry` a `PaginatedResponse` typy jsou správné

## Implementační fáze

### Fáze 1: Backend + fix + docs (jedna koherentní změna)

1. Vytvořit `internal/api/audit.go` s `handleListAudit`
2. Registrovat route v `server.go`
3. Opravit `paginatedResponse` field `items` → `data`
4. Opravit UI event type konstanty
5. Aktualizovat OpenAPI spec
6. Aktualizovat initial-analyse.md
7. Napsat testy

## Rizika a mitigace

| Riziko | Dopad | Pravděpodobnost | Mitigace |
|--------|-------|-----------------|----------|
| Změna `items` → `data` rozbije Artifacts stránku | Střední | Nízká — UI již očekává `data` | Ověřit že Artifacts stránka funguje se stejným typem |
| Event type mismatch s existujícími daty v DB | Nízký | N/A | Go model se nemění, UI se přizpůsobí |

## Testování

### Unit testy
- `TestHandleListAudit_Empty_ReturnsEmptyArray` — prázdná DB vrátí `{data: [], total: 0}`
- `TestHandleListAudit_WithEvents_ReturnsPaginated` — vložit záznamy, ověřit stránkování
- `TestHandleListAudit_FilterByEventType_ReturnsFiltered` — filtr `event_type=BLOCKED`

### Verifikace
- `make test`
- `make build`

## Poznámky

- Pagination field mismatch (`items` vs `data`) je bug napříč všemi stránkovanými endpointy, ne jen audit. Fix opraví i artifacts endpoint.
- Audit log je append-only (security invariant #5) — endpoint je read-only, žádné riziko porušení.
