package org.owasp.dependencycheck.data.ossindex.detectors;

import org.owasp.dependencycheck.analyzer.ComposerLockAnalyzer;
import org.owasp.dependencycheck.data.ossindex.PackageDetector;

/**
 * Composer (PHP) {@link PackageDetector}.
 *
 * @since ???
 */
public class ComposerDetector extends PackageDetectorSupport {
    public static final String COMPOSER = "composer";

    public ComposerDetector() {
        super(COMPOSER, ComposerLockAnalyzer.DEPENDENCY_ECOSYSTEM);
    }
}
