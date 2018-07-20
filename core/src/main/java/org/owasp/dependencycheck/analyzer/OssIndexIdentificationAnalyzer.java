package org.owasp.dependencycheck.analyzer;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.ossindex.PackageDetector;
import org.owasp.dependencycheck.dependency.*;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.goodies.packageurl.PackageUrl;

import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;
import java.util.Set;

/**
 * Identify packages from dependencies suitable for analysis with Sonatype OSS Index.
 *
 * This is split off from {@link OssIndexAnalyzer} to allow package identification information to be potentially
 * re-used by other analyzers.
 *
 * @since ???
 *
 * @see OssIndexAnalyzer
 * @see PackageDetector
 */
public class OssIndexIdentificationAnalyzer extends AbstractAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(OssIndexIdentificationAnalyzer.class);

    public static final String IDENTIFIER_TYPE = "ossindex";

    private List<PackageDetector> detectors;

    @Override
    public String getName() {
        return "Sonatype OSS Index Analyzer: Identification";
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.POST_IDENTIFIER_ANALYSIS;
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_OSSINDEX_ENABLED;
    }

    @Override
    protected void prepareAnalyzer(final Engine engine) throws InitializationException {
        detectors = loadDetectors();

        if (log.isDebugEnabled()) {
            log.debug("Detectors:");
            for (PackageDetector detector : detectors) {
                log.debug("  {}", detector);
            }
        }
    }

    @Override
    protected void closeAnalyzer() throws Exception {
        detectors = null;
    }

    private List<PackageDetector> loadDetectors() {
        List<PackageDetector> detectors = new ArrayList<>();
        for (PackageDetector detector : ServiceLoader.load(PackageDetector.class)) {
            detectors.add(detector);
        }
        return detectors;
    }

    @Override
    protected void analyzeDependency(final Dependency dependency, final Engine engine) throws AnalysisException {
        if (detectors == null) {
            throw new IllegalStateException();
        }

        PackageUrl purl = identify(dependency);
        if (purl != null) {
            Identifier id = new Identifier(IDENTIFIER_TYPE, purl.toString(), null);
            // FIXME: confidence is optional on Identifier, but required to be set to avoid NPE in report generation
            id.setConfidence(Confidence.HIGH);
            dependency.addIdentifier(id);
        }
    }

    @Nullable
    private PackageUrl identify(final Dependency dependency) {
        log.debug("Identify dependency: {}", dependency);

        if (log.isDebugEnabled()) {
            explain(dependency);
        }

        for (PackageDetector detector : detectors) {
            log.debug("Detecting with: {}", detector);
            PackageUrl purl = detector.detect(dependency);

            // first detected wins
            if (purl != null) {
                log.debug("  Package: {}", purl);
                return purl;
            }
        }

        return null;
    }

    private void explain(final Dependency dependency) {
        log.debug("  Ecosystem: {}", dependency.getEcosystem());
        log.debug("  Name: {}", dependency.getName());
        log.debug("  Version: {}", dependency.getVersion());
        log.debug("  Virtual: {}", dependency.isVirtual());

        log.debug("  Identifiers:");
        for (Identifier i : dependency.getIdentifiers()) {
            log.debug("    {} {}", i, i.getConfidence());
        }

        log.debug("  Evidence:");
        explainEvidence(dependency, EvidenceType.VENDOR);
        explainEvidence(dependency, EvidenceType.PRODUCT);
        explainEvidence(dependency, EvidenceType.VERSION);
    }

    private void explainEvidence(final Dependency dependency, final EvidenceType type) {
        Set<Evidence> evidence = dependency.getEvidence(type);
        if (!evidence.isEmpty()) {
            log.debug("    {}", type);
            for (Evidence e : evidence) {
                log.debug("      {}", e);
            }
        }
    }
}