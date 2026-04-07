# Dependency Graph Visualization

> Visual representation of dependency relationships between cached artifacts and their downstream consumers.

**Status:** Planned (v1.2+)
**Origin:** Initial analysis roadmap, section 15

## Problem

When a vulnerability or supply chain attack is discovered in a package, security teams need to quickly answer: "Who in our organization is using this package, and what depends on it?" Currently, Shieldoo Gate logs which artifacts were served to which clients, but there is no way to visualize or query dependency relationships.

## Proposed Solution

Build a dependency graph that tracks relationships between artifacts and provides visualization and query capabilities through the Admin UI.

### Key Requirements

1. **Dependency extraction:** Parse dependency declarations from cached artifacts:
   - **PyPI:** `METADATA` (`Requires-Dist`), `setup.py`, `pyproject.toml`
   - **npm:** `package.json` (`dependencies`, `devDependencies`)
   - **NuGet:** `.nuspec` (`<dependencies>`)
   - **Maven:** `pom.xml` (`<dependencies>`)
   - **RubyGems:** Gemspec (`add_dependency`, `add_runtime_dependency`)
   - **Go:** `go.mod` (`require` directives)

2. **Graph storage:** New database tables:
   ```
   artifact_dependencies (
     artifact_id TEXT FK,       -- the artifact that declares the dependency
     depends_on_ecosystem TEXT,
     depends_on_name TEXT,
     depends_on_version_constraint TEXT,  -- e.g., ">=2.0,<3.0"
     scope TEXT                           -- "runtime", "dev", "build"
   )
   ```

3. **Impact analysis API:**
   - `GET /api/v1/artifacts/{id}/dependents` — who depends on this artifact?
   - `GET /api/v1/artifacts/{id}/dependencies` — what does this artifact depend on?
   - `GET /api/v1/graph/impact?ecosystem=pypi&name=litellm` — full impact tree for a package

4. **UI visualization:**
   - Interactive dependency graph on the artifact detail page
   - "Impact analysis" view: starting from a quarantined/blocked package, show all cached artifacts that directly or transitively depend on it
   - Color coding: green (clean), yellow (suspicious), red (quarantined)

5. **Blast radius estimation:** When an artifact is quarantined, automatically compute and display the number of affected downstream artifacts and client IPs that have downloaded them.

### How It Fits Into the Architecture

- **Scan Engine:** Add a `DependencyExtractor` component (or integrate into SBOM generation) that runs during the scan phase and populates the `artifact_dependencies` table.
- **Admin API:** New endpoint group under `/api/v1/graph/`.
- **Admin UI:** New "Dependencies" tab on artifact detail page + standalone "Impact Analysis" page.
- **Alerting:** Include blast radius count in quarantine/block alert payloads.

### Considerations

- **Cross-ecosystem dependencies:** Some packages depend on packages from other ecosystems (e.g., a Python package that shells out to an npm tool). The graph should support cross-ecosystem edges, but detection is limited to declared dependencies.
- **Version resolution:** The proxy sees specific versions that were requested, not the full resolution tree. The graph represents "what was actually downloaded through the proxy," not "what could theoretically be resolved."
- **Storage growth:** For large organizations proxying thousands of packages, the dependency graph can grow significantly. Consider pruning edges for artifacts that have been evicted from the cache.
- **Synergy with SBOM:** If SBOM generation is implemented first, dependency extraction becomes trivial — just parse the SBOM. Consider building this feature on top of SBOM data.
