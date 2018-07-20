/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cwe;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.Map;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.SAXException;

/**
 * Utility application to process and serialize the CWE data. This class should
 * be used with the 'research concepts' view from
 * https://cwe.mitre.org/data/downloads.html.
 *
 * @author Jeremy Long
 */
public class App {

    /**
     * The main method for the application.
     *
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        File in;
        File out;
        if (args.length == 0) {
            System.err.println("Incorrect arguments - please provide one or more files as input");
            System.err.println("Download the research concepts, developer concepts, and architectural concepts view of the CWE from "
                    + "https://cwe.mitre.org/data/downloads.html");
            return;
        }
        in = new File(args[0]);
        if (!in.isFile()) {
            System.err.println(String.format("%s does not exist", in.getAbsolutePath()));
            return;
        }
        out = new File("cwe.hashmap.serialized");
        Map<String, String> cwe = readCweData(args);
        serializeCweData(cwe, out);
    }

    private static Map<String, String> readCweData(String[] files) {
        try {
            final SAXParserFactory factory = SAXParserFactory.newInstance();
            final SAXParser saxParser = factory.newSAXParser();
            final CweHandler handler = new CweHandler();
            for (String f : files) {
                final File in = new File(f);
                if (!in.isFile()) {
                    System.err.println(String.format("File not found %s", in));
                }
                System.out.println(String.format("Parsing %s", in));
                saxParser.parse(in, handler);
            }
            return handler.getCwe();
        } catch (SAXException | IOException | ParserConfigurationException ex) {
            System.err.println(String.format("Error generating serialized data: %s", ex.getMessage()));
        }
        return null;
    }

    private static void serializeCweData(Map<String, String> cwe, File out) {
        try (FileOutputStream fout = new FileOutputStream(out);
                ObjectOutputStream objOut = new ObjectOutputStream(fout);) {
            System.out.println("Writing " + cwe.size() + " cwe entries.");
            objOut.writeObject(cwe);
            System.out.println(String.format("Serialized CWE data written to %s", out.getCanonicalPath()));
            System.out.println("To update the ODC CWE data copy the serialized file to 'src/main/resources/data/cwe.hashmap.serialized'");
        } catch (IOException ex) {
            System.err.println(String.format("Error generating serialized data: %s", ex.getMessage()));
        }
    }
}
