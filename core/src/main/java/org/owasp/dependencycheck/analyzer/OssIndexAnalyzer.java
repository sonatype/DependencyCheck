package org.owasp.dependencycheck.analyzer;

import org.sonatype.ossindex.service.api.componentreport.ComponentReport;
import org.sonatype.ossindex.service.api.componentreport.ComponentReportVulnerability;
import org.sonatype.ossindex.service.client.OssindexClient;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.ossindex.OssindexClientFactory;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.goodies.packageurl.PackageUrl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.owasp.dependencycheck.analyzer.OssIndexIdentificationAnalyzer.IDENTIFIER_TYPE;

/**
 * Enrich dependency information from Sonatype OSS index.
 *
 * @since ???
 *
 * @see OssIndexIdentificationAnalyzer
 */
public class OssIndexAnalyzer extends AbstractAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(OssIndexAnalyzer.class);

    public static final String REFERENCE_TYPE = "ossindex";

    private OssindexClient client;

    private Map<PackageUrl,ComponentReport> reports;

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
        client = OssindexClientFactory.create(getSettings());
    }

    @Override
    protected void closeAnalyzer() throws Exception {
        client = null;
        reports = null;
    }

    @Override
    protected void analyzeDependency(final Dependency dependency, final Engine engine) throws AnalysisException {
        if (client == null) {
            throw new IllegalStateException();
        }

        // batch request package-reports for all dependencies
        synchronized (this) {
            if (reports == null) {
                try {
                    reports = requestReports(engine.getDependencies());
                }
                catch (Exception e) {
                    throw new AnalysisException("Failed to request package-reports", e);
                }
            }
        }

        enrich(dependency);
    }

    /**
     * Batch request package-reports for all dependencies.
     */
    private Map<PackageUrl, ComponentReport> requestReports(final Dependency[] dependencies) throws Exception {
        log.debug("Requesting package-reports for {} dependencies", dependencies.length);

        // create requests for each dependency which has a package-identifier
        List<PackageUrl> packages = new ArrayList<>();
        for (Dependency dependency : dependencies) {
            for (Identifier id : dependency.getIdentifiers()) {
                if (IDENTIFIER_TYPE.equals(id.getType())) {
                    PackageUrl purl = PackageUrl.parse(id.getValue());
                    packages.add(purl);
                }
            }
        }

        return client.requestComponentReports(packages);
    }

    private void enrich(final Dependency dependency) {
        log.debug("Enrich dependency: {}", dependency);

        for (Identifier id : dependency.getIdentifiers()) {
            if (IDENTIFIER_TYPE.equals(id.getType())) {
                log.debug("  Package: {} -> {}", id, id.getConfidence());

                PackageUrl purl = PackageUrl.parse(id.getValue());
                try {
                    ComponentReport report = reports.get(purl);
                    if (report == null) {
                        throw new IllegalStateException("Missing package-report for: " + purl);
                    }

                    // expose the URL to the package details for report generation
                    id.setUrl(report.getReference().toString());

                    for (ComponentReportVulnerability vuln : report.getVulnerabilities()) {
                        dependency.addVulnerability(transform(report, vuln));
                    }
                }
                catch (Exception e) {
                    log.warn("Failed to fetch package-report for: {}", purl, e);
                }
            }
        }
    }

    private Vulnerability transform(final ComponentReport report, final ComponentReportVulnerability source) {
        Vulnerability result = new Vulnerability();
        result.setSource(Vulnerability.Source.OSSINDEX);

        result.setName(String.format("%s: %s", source.getId(), source.getTitle()));
        result.setDescription(source.getDescription());
        if (source.getCvssScore() != null) {
            result.setCvssScore(source.getCvssScore());
        }
        result.setCvssAccessVector(source.getCvssVector());
        result.setCwe(source.getCwe());

        // generate a reference to the vulnerability details on OSS Index
        result.addReference(REFERENCE_TYPE,
                String.format("%s: %s", source.getId(), source.getTitle()),
                source.getReference().toString());

        // TODO: its not really clear what this is and how it maps the OSS Index report
        VulnerableSoftware software = new VulnerableSoftware();
        software.setName(report.getCoordinates().getName());
        software.setVersion(report.getCoordinates().getVersion());
        result.setVulnerableSoftware(Collections.singleton(software));

        return result;
    }
}