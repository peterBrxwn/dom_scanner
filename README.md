# DOM XSS Scanner Burp Extension

## Overview

DOM XSS Scanner is a Burp Suite extension designed to identify potential DOM-based Cross-Site Scripting (XSS) vulnerabilities in JavaScript responses. It scans JavaScript content for known dangerous sinks that could be exploited if user-controlled input is not properly sanitized.

## Features

-   Automatically analyzes JavaScript responses for potential DOM XSS sinks.
-   Highlights identified sinks in Burp Suite's HTTP message editor with a blue highlight.
-   Logs identified sinks to Burp Suite's issue activity log.
-   Scans for a comprehensive list of commonly exploited JavaScript sinks.

## Installation

1.  Open Burp Suite.
2.  Navigate to `Extender` > `Extensions`.
3.  Click `Add`.
4.  Select `Java` as the extension type.
5.  Load the compiled `DomScanner.jar` file.

## Usage

-   Once loaded, the extension will automatically intercept and analyze JavaScript responses.
-   Potential DOM XSS sinks found in JavaScript will be highlighted in blue in the HTTP message editor.
-   Detailed information about identified sinks will be logged in Burp Suite's issue activity log.

## Detected Sinks

The extension scans for the following JavaScript sinks:

-   `eval`
-   `setTimeout`
-   `setInterval`
-   `Function`
-   `execScript`
-   `document.write`
-   `innerHTML`
-   `outerHTML`
-   `insertAdjacentHTML`
-   `location`
-   `localStorage`
-   `sessionStorage`
-   `document.cookie`
-   `window.name`
-   `window.open`
-   `postMessage`
-   `onmessage`
-   `$.html` (jQuery)
-   `$.append` (jQuery)
-   `$.prepend` (jQuery)
-   `$.before` (jQuery)
-   `$.after` (jQuery)
-   `$.wrap` (jQuery)
-   `$.wrapAll` (jQuery)
-   `$.replaceWith` (jQuery)
-   `$.text` (jQuery)

## Important Notes

-   This extension helps identify potential DOM XSS vulnerabilities. It does not guarantee the existence of a vulnerability.
-   Proper input sanitization and output encoding are crucial for preventing DOM XSS.
-   Always manually verify identified sinks and assess the context in which they are used.

## Contributing

If you would like to contribute or suggest additional sink patterns, feel free to submit a pull request or open an issue.

## License

Copyright (c) 2022-2023 PortSwigger Ltd. All rights reserved.