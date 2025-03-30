/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package gg.domscanner;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.logging.Logging;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.*;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

public class DomScanner implements BurpExtension, HttpHandler {
    private static final List<Pattern> sinkPatterns = new ArrayList<>();
    private Logging logging;

    @Override
    public void initialize(MontoyaApi api)
    {
        api.extension().setName("DOM XSS Scanner");
        api.http().registerHttpHandler(this);
        logging = api.logging();
        loadSinkPatterns();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        Annotations annotations = responseReceived.annotations();
        String contentType = responseReceived.mimeType().name().toLowerCase();
        boolean foundSink = false;

        // Check if the response is JavaScript
        if (contentType.equals("script")) {
            String responseBody = responseReceived.body().toString();

            for (Pattern pattern : sinkPatterns) {
                Matcher matcher = pattern.matcher(responseBody);
                if (matcher.find()) {
                    logging.raiseInfoEvent("[+] Potential DOM XSS sink found: " + matcher.group() + " in " + responseReceived.initiatingRequest().url());
                    foundSink = true;
                }
            }
        }

        // If a sink is found, update the annotations
        if (foundSink) {
            annotations = annotations.withHighlightColor(HighlightColor.BLUE);
        }

        // Return the response with updated annotations
        return continueWith(responseReceived, annotations);
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
