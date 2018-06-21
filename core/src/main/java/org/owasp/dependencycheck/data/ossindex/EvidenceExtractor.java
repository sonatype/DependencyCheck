package org.owasp.dependencycheck.data.ossindex;

import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.Arrays;

/**
 * Helper to extract {@link Evidence} from a {@link Dependency}.
 *
 * @since ???
 */
public class EvidenceExtractor {
    private static final Logger log = LoggerFactory.getLogger(EvidenceExtractor.class);

    // TODO: maybe consider ignoring LOW?
    private Confidence[] confidences = Confidence.values();

    private EvidenceType[] types;

    private String[] names;

    private String[] sources;

    public EvidenceExtractor confidences(final Confidence... confidences) {
        this.confidences = confidences;
        return this;
    }

    public EvidenceExtractor types(final EvidenceType... types) {
        this.types = types;
        return this;
    }

    public EvidenceExtractor names(final String... names) {
        this.names = names;
        return this;
    }

    public EvidenceExtractor sources(final String ...sources) {
        this.sources = sources;
        return this;
    }

    @Nullable
    public Evidence extract(final Dependency dependency) {
        if (dependency == null) {
            throw new NullPointerException();
        }
        if (confidences == null) {
            throw new IllegalStateException();
        }
        if (types == null) {
            throw new IllegalStateException();
        }
        if (names == null) {
            throw new IllegalStateException();
        }
        if (sources == null) {
            throw new IllegalStateException();
        }

        log.debug("Extract: types={}, names={}, sources={}", types, Arrays.asList(names), Arrays.asList(sources));

        for (Confidence confidence : confidences) {
            for (EvidenceType type : types) {
                for (Evidence evidence : dependency.getIterator(type, confidence)) {
                    log.debug("  Checking: {}", evidence);
                    for (String name : names) {
                        for (String source : sources) {
                            if (name.equals(evidence.getName()) && source.equals(evidence.getSource())) {
                                log.debug("    Found: {}", evidence);
                                return evidence;
                            }
                        }
                    }
                }
            }
        }

        return null;
    }
}
