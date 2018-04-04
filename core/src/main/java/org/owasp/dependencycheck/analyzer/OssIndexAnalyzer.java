package org.owasp.dependencycheck.analyzer;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.ossindex.OssIndexFactory;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.ossindex.client.OssIndex;
import org.sonatype.ossindex.client.PackageIdentifier;
import org.sonatype.ossindex.client.PackageReport;
import org.sonatype.ossindex.client.PackageRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static com.google.common.base.Preconditions.checkState;
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

    private OssIndex index;

    private Map<PackageRequest,PackageReport> reports;

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
        index = OssIndexFactory.create(getSettings());
    }

    @Override
    protected void closeAnalyzer() throws Exception {
        index = null;
        reports = null;
    }

    @Override
    protected void analyzeDependency(final Dependency dependency, final Engine engine) throws AnalysisException {
        checkState(index != null);

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
    private Map<PackageRequest, PackageReport> requestReports(final Dependency[] dependencies) throws Exception {
        log.debug("Requesting package-reports for {} dependencies", dependencies.length);

        // create requests for each dependency which has a package-identifier
        List<PackageRequest> requests = new ArrayList<>();
        for (Dependency dependency : dependencies) {
            for (Identifier id : dependency.getIdentifiers()) {
                if (IDENTIFIER_TYPE.equals(id.getType())) {
                    PackageIdentifier pid = PackageIdentifier.parse(id.getValue());
                    requests.add(pid.toRequest());
                }
            }
        }

        return index.request(requests);
    }

    private void enrich(final Dependency dependency) {
        log.debug("Enrich dependency: {}", dependency);

        for (Identifier id : dependency.getIdentifiers()) {
            if (IDENTIFIER_TYPE.equals(id.getType())) {
                log.debug("  Package: {} -> {}", id, id.getConfidence());

                PackageIdentifier pid = PackageIdentifier.parse(id.getValue());
                try {
                    PackageReport report = reports.get(pid.toRequest());
                    checkState(report != null, "Missing package-report for: %s", pid);

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
        result.addReference(REFERENCE_TYPE,
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