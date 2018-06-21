Tasks
====================

Task                                                     | Description
---------------------------------------------------------|-----------------------
[dependencyCheckAnalyze](configuration.html)             | Runs dependency-check against the project and generates a report.
[dependencyCheckAggregate](configuration-aggregate.html) | Runs dependency-check against a multi-project build and generates a report.
dependencyCheckUpdate                                    | Updates the local cache of the NVD data from NIST.
[dependencyCheckPurge](configuration-purge.html)         | Deletes the local copy of the NVD. This is used to force a refresh of the data.

Configuration
====================

```groovy
buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath 'org.owasp:dependency-check-gradle:${project.version}'
    }
}
apply plugin: 'org.owasp.dependencycheck'

check.dependsOn dependencyCheckUpdate
```

Property             | Description                        | Default Value
---------------------|------------------------------------|------------------
cveValidForHours     | Sets the number of hours to wait before checking for new updates from the NVD.                                     | 4
failOnError          | Fails the build if an error occurs during the dependency-check analysis.                                           | true

#### Example
```groovy
dependencyCheck {
    cveValidForHours=1
}
```

### Proxy Configuration

Config Group | Property          | Description                        | Default Value
-------------|-------------------|------------------------------------|------------------
proxy        | server            | The proxy server.                  | &nbsp;
proxy        | port              | The proxy port.                    | &nbsp;
proxy        | username          | Defines the proxy user name.       | &nbsp;
proxy        | password          | Defines the proxy password.        | &nbsp;

#### Example
```groovy
dependencyCheck {
    proxy {
        server=some.proxy.server
        port=8989
    }
}
```

### Advanced Configuration

The following properties can be configured in the dependencyCheck task. However, they are less frequently changed. One exception
may be the cvedUrl properties, which can be used to host a mirror of the NVD within an enterprise environment.
Note, if ANY of the cve configuration group are set - they should all be set to ensure things work as expected.

Config Group | Property          | Description                                                                                 | Default Value
-------------|-------------------|---------------------------------------------------------------------------------------------|------------------
cve          | url12Modified     | URL for the modified CVE 1.2.                                                               | https://nvd.nist.gov/feeds/xml/cve/1.2/nvdcve-modified.xml.gz
cve          | url20Modified     | URL for the modified CVE 2.0.                                                               | https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-Modified.xml.gz
cve          | url12Base         | Base URL for each year's CVE 1.2, the %d will be replaced with the year.                    | https://nvd.nist.gov/feeds/xml/cve/1.2/nvdcve-%d.xml.gz
cve          | url20Base         | Base URL for each year's CVE 2.0, the %d will be replaced with the year.                    | https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-%d.xml.gz
data         | directory         | Sets the data directory to hold SQL CVEs contents. This should generally not be changed.    | &nbsp;
data         | driver            | The name of the database driver. Example: org.h2.Driver.                                    | &nbsp;
data         | driverPath        | The path to the database driver JAR file; only used if the driver is not in the class path. | &nbsp;
data         | connectionString  | The connection string used to connect to the database.                                      | &nbsp;
data         | username          | The username used when connecting to the database.                                          | &nbsp;
data         | password          | The password used when connecting to the database.                                          | &nbsp;

#### Example
```groovy
dependencyCheck {
    data {
        directory='d:/nvd'
    }
}
```
