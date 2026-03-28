# Maven Example — commons-lang3

Installs `commons-lang3` via the Shieldoo Gate Maven proxy and runs a minimal string manipulation example.

## Prerequisites

- Java 11+ (`java -version`)
- Maven 3.6+ (`mvn -version`)
- Shieldoo Gate running locally with the Maven proxy enabled on port `8085`

## Run

```bash
# Resolve dependencies through the Shieldoo proxy
mvn dependency:resolve

# Compile and run
mvn compile exec:java -Dexec.mainClass="Example"
```

Or simply verify the dependency resolution:

```bash
mvn dependency:resolve -U
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
- JAR download (`commons-lang3-3.14.0.jar`) goes through the scan pipeline
- Check the admin UI at `http://localhost:8080` to see the scanned artifacts
