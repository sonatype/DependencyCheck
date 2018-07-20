Sonatype OSS Index Analyzer
====================

OWASP dependency-check includes an analyzer that will detect software packages
and checks the [Sonatype OSS Index][1] if the package contains vulnerability information
to include in the report.

Package detection is based on evidence collected from other analyzers and generates
a normalized package identifier that is attached to the dependency information.

Normalized package identifiers are roughly [PURL-ish][2]:

    <format>:[<namespace>/]<name>@<version

After packages have been identified, when collecting information,
additional details if available are included into the report. 

[1]: https://ossindex.sonatype.org "Sonatype OSS Index"
[2]: https://github.com/package-url/purl-spec