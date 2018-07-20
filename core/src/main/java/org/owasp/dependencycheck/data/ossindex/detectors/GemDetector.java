package org.owasp.dependencycheck.data.ossindex.detectors;

import org.owasp.dependencycheck.analyzer.RubyGemspecAnalyzer;
import org.owasp.dependencycheck.data.ossindex.PackageDetector;

/**
 * Gem (Ruby) {@link PackageDetector}.
 *
 * @since ???
 */
public class GemDetector extends PackageDetectorSupport {
    public static final String GEM = "gem";

    public GemDetector() {
        super(GEM, RubyGemspecAnalyzer.DEPENDENCY_ECOSYSTEM);
    }
}
