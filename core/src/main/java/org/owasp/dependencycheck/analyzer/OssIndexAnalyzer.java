package org.owasp.dependencycheck.analyzer;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.ossindex.OssIndex;
import org.owasp.dependencycheck.data.ossindex.PackageIdentifier;
import org.owasp.dependencycheck.data.ossindex.PackageReport;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;

/**
 * Enrich dependency information from Sonatype OSS index.
 *
 * @since ???
 *
 * @see OssIndexIdentificationAnalyzer
 */
public class OssIndexAnalyzer extends AbstractAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(OssIndexAnalyzer.class);

    private OssIndex index;

    @Override
    public String getName() {
        return "Sonatype OSS Index Analyzer";
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.FINDING_ANALYSIS;
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_OSSINDEX_ENABLED;
    }

    @Override
    protected void prepareAnalyzer(final Engine engine) throws InitializationException {
        index = new OssIndex(getSettings());
    }

    @Override
    protected void closeAnalyzer() throws Exception {
        index = null;
    }

    // HACK: sync for logging sanity only
    @Override
    protected synchronized void analyzeDependency(final Dependency dependency, final Engine engine) throws AnalysisException {
        if (index == null) {
            throw new IllegalStateException();
        }

        enrich(dependency);
    }

    private void enrich(final Dependency dependency) {
        log.debug("Enrich dependency: {}", dependency);

        for (Identifier id : dependency.getIdentifiers()) {
            if (PackageIdentifier.TYPE.equals(id.getType())) {
                log.debug("  Package: {} -> {}", id, id.getConfidence());

                PackageIdentifier pid = PackageIdentifier.parse(id.getValue());
                try {
                    PackageReport report = index.request(pid);

                    // expose the URL to the package details for report generation
                    id.setUrl(index.packageUrl(report).toExternalForm());

                    for (PackageReport.Vulnerability vuln : report.getVulnerabilities()) {
                        dependency.addVulnerability(transform(report, vuln));
                    }
                }
                catch (Exception e) {
                    log.warn("Failed to fetch package-report for: {}", pid, e);
                }
            }
        }
    }

    private Vulnerability transform(final PackageReport report, final PackageReport.Vulnerability source) {
        Vulnerability result = new Vulnerability();
        result.setSource(Vulnerability.Source.OSSINDEX);

        result.setName(String.format("%s: %s", source.getId(), source.getTitle()));
        result.setDescription(source.getDescription());

        // generate a reference to the vulnerability details on OSS Index
        result.addReference("ossindex",
                String.format("%s: %s", source.getId(), source.getTitle()),
                index.referenceUrl(source).toExternalForm());

        // TODO: its not really clear what this is and how it maps the OSS Index report
        VulnerableSoftware software = new VulnerableSoftware();
        software.setName(report.getName());
        software.setVersion(report.getVersion());
        result.setVulnerableSoftware(Collections.singleton(software));

        // TODO: some key information, like severity and cvss details which the report wants, are missing
        // TODO: what else can we transform here?

        return result;
    }
}