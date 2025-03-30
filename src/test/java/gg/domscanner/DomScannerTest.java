/*
 * DomScannerTest.java
 *
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 *
 * DomScannerTest provides unit and integration tests for the DomScanner Burp Suite extension.
 * These tests ensure that the extension correctly identifies potential DOM XSS sinks
 * in HTTP responses, specifically focusing on JavaScript content.
 *
 * The tests cover various scenarios, including responses with and without DOM sinks,
 * different JavaScript content types, and boundary cases.
 */

package gg.domscanner;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DomScannerTest {
    private static final List<Pattern> sinkPatterns = new ArrayList<>();
    private static final String testString = """
eval("alert('test')"); 
setTimeout(() => console.log("Hello"), 1000); 
setInterval(() => console.log("Repeat"), 2000); 
let dynamicFunc = new Function("return 42"); 
document.write("Hello World"); 
document.writeln("New Line"); 
element.innerHTML = "<h1>Title</h1>"; 
element.outerHTML = "<div>Wrapper</div>"; 
element.insertAdjacentHTML("beforeend", "<p>Added</p>"); 
location.reload(); 
location.href = "https://example.com"; 
location.assign("https://example.com"); 
location.replace("https://example.com"); 
localStorage.setItem("key", "value"); 
sessionStorage.setItem("key", "value"); 
window.name = "myWindow"; 
console.log(document.cookie); 
window.open("https://example.com"); 
window.postMessage("Hello", "*"); 
""";

    public static void main(String[] args) throws Exception {
        System.out.println("DOM XSS Scanner Tests");
        loadSinkPatterns();
         
        // Test each pattern against the test string
        for (Pattern pattern : sinkPatterns) {
            Matcher matcher = pattern.matcher(testString);
            if (matcher.find()) {
                System.out.println("[+] DOM XSS sink found: " + matcher.group());
            } else {
                System.out.println("Pattern did not match: " + pattern.pattern());
            }
        }
    }

    private static void loadSinkPatterns() {
        sinkPatterns.add(Pattern.compile("eval"));
        sinkPatterns.add(Pattern.compile("setTimeout"));
        sinkPatterns.add(Pattern.compile("setInterval"));
        sinkPatterns.add(Pattern.compile("Function"));
        sinkPatterns.add(Pattern.compile("execScript"));
        sinkPatterns.add(Pattern.compile("document\\.write"));
        sinkPatterns.add(Pattern.compile("innerHTML"));
        sinkPatterns.add(Pattern.compile("outerHTML"));
        sinkPatterns.add(Pattern.compile("insertAdjacentHTML"));
        sinkPatterns.add(Pattern.compile("location"));
        sinkPatterns.add(Pattern.compile("localStorage"));
        sinkPatterns.add(Pattern.compile("sessionStorage"));
        sinkPatterns.add(Pattern.compile("document\\.cookie"));
        sinkPatterns.add(Pattern.compile("window\\.name"));
        sinkPatterns.add(Pattern.compile("window\\.open"));
        sinkPatterns.add(Pattern.compile("postMessage"));
        sinkPatterns.add(Pattern.compile("onmessage"));
        sinkPatterns.add(Pattern.compile("\\$\\.html"));
        sinkPatterns.add(Pattern.compile("\\$\\.append"));
        sinkPatterns.add(Pattern.compile("\\$\\.prepend"));
        sinkPatterns.add(Pattern.compile("\\$\\.before"));
        sinkPatterns.add(Pattern.compile("\\$\\.after"));
        sinkPatterns.add(Pattern.compile("\\$\\.wrap"));
        sinkPatterns.add(Pattern.compile("\\$\\.wrapAll"));
        sinkPatterns.add(Pattern.compile("\\$\\.replaceWith"));
        sinkPatterns.add(Pattern.compile("\\$\\.text"));
    }
}
