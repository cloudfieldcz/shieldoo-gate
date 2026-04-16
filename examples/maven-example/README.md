# Maven Example — commons-lang3

Installs `commons-lang3` via the Shieldoo Gate Maven proxy and runs a minimal string manipulation example.

## Prerequisites

- Java 11+ (`java -version`)
- Maven 3.6+ (`mvn -version`)
- Shieldoo Gate running locally with the Maven proxy enabled on port `8085`

## Authentication

The reference `docker/config.yaml` enables proxy auth with a well-known **development token** (`test-token-123`) and the **project label** `maven-demo`.

Maven reads credentials from `~/.m2/settings.xml` (keyed by `<server><id>`). This example keeps the configuration self-contained in `settings.xml` next to `pom.xml` — pass it explicitly to every `mvn` command with `--settings settings.xml`.

```xml
<!-- settings.xml -->
<server>
  <id>shieldoo</id>
  <username>maven-demo</username>   <!-- = project label -->
  <password>test-token-123</password>
</server>
```

The server `<id>shieldoo</id>` must match the `<repository><id>shieldoo</id>` entry in `pom.xml` — that's how Maven binds credentials to a repository.

## Run

```bash
# Resolve dependencies through the Shieldoo proxy (uses local settings.xml)
mvn --settings settings.xml dependency:resolve

# Compile and run
mvn --settings settings.xml compile exec:java -Dexec.mainClass="Example"
```

## Expected Output

```
Original:    hello from shieldoo gate
Capitalized: Hello from shieldoo gate
Reversed:    etag oodleihs morf olleh
Is blank:    false

commons-lang3 loaded successfully!
Done!
```

## What This Tests

- Maven proxy on `localhost:8085` correctly proxies Maven Central repository metadata and artifacts
- `<server>` credentials are sent as Basic Auth — username `maven-demo` becomes the project label
- JAR download (`commons-lang3-3.14.0.jar`) goes through the scan pipeline and is stamped with `project_id = maven-demo` in the audit log
- Verify in the admin UI at `http://localhost:8080`:
  - `Projects` tab → `maven-demo` with its artifact usage
  - `Audit Log` tab → each artifact fetch tagged with the project
