package org.owasp.dependencycheck.data.ossindex;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

/**
 * Tests for {@link PackageIdentifier}.
 */
public class PackageIdentifierTest {
    @Test
    public void valueRepresentation() {
        PackageIdentifier id = new PackageIdentifier("foo", "bar", "baz");
        assertThat(id.getValue(), is("foo:bar@baz"));
    }

    @Test
    public void parseValid() {
        PackageIdentifier id = PackageIdentifier.parse("foo:bar@baz");
        assertThat(id.getFormat(), is("foo"));
        assertThat(id.getName(), is("bar"));
        assertThat(id.getVersion(), is("baz"));
    }

    @Test
    public void parseInvalid() {
        try {
            PackageIdentifier.parse("not.a.package.identifier");
            fail();
        }
        catch (Exception e) {
            // expected
        }
    }
}
