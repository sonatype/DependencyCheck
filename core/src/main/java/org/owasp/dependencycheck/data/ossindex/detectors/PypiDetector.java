package org.owasp.dependencycheck.data.ossindex.detectors;

import org.owasp.dependencycheck.analyzer.PythonDistributionAnalyzer;
import org.owasp.dependencycheck.analyzer.PythonPackageAnalyzer;
import org.owasp.dependencycheck.data.ossindex.PackageDetector;

/**
 * PyPI (Python) {@link PackageDetector}.
 *
 * @since ???
 */
public class PypiDetector extends PackageDetectorSupport {
    public static final String FORMAT = "pypi";

    public PypiDetector() {
        super(FORMAT, PythonPackageAnalyzer.DEPENDENCY_ECOSYSTEM, PythonDistributionAnalyzer.DEPENDENCY_ECOSYSTEM);
    }
}
