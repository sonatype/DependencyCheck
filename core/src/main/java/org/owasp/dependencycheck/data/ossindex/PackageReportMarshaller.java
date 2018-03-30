package org.owasp.dependencycheck.data.ossindex;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;

/**
 * {@link PackageReport} marshaller.
 *
 * @since ???
 */
public class PackageReportMarshaller {
    private final Gson parser;

    public PackageReportMarshaller() {
        parser = new GsonBuilder()
                .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                .create();
    }

    private static final TypeToken<List<PackageReport>> LIST_PACKAGE_REPORT = new TypeToken<List<PackageReport>>() {};

    public List<PackageReport> unmarshal(final InputStream input) {
        return parser.fromJson(new InputStreamReader(input), LIST_PACKAGE_REPORT.getType());
    }
}
