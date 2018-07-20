package org.owasp.dependencycheck.data.ossindex.detectors;

import org.owasp.dependencycheck.analyzer.NodePackageAnalyzer;
import org.owasp.dependencycheck.data.ossindex.PackageDetector;

/**
 * NPM {@link PackageDetector}.
 *
 * @since ???
 */
public class NpmDetector extends PackageDetectorSupport {
    public static final String FORMAT = "npm";

    public NpmDetector() {
        super(FORMAT, NodePackageAnalyzer.DEPENDENCY_ECOSYSTEM);
    }
}
