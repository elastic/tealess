
![tealess](tealess.png)

----

NOTE: This project is not yet ready for general use. We're still figuring out
what we want it to do and what interfaces it should provide for users. Because of this, much of the code is in an active-exploration phase where there are lots of commented-out code, unused areas, and plenty of areas for improvement.

----

# Introduction

Overview: This project is intended to provide tooling that bridges several gaps
users have with various SSL/TLS.

Goals:

* Provide actionable diagnostic and error messages for SSL/TLS problems.
* Clearer explanations of problems when they occur.
* Help users break the habit of disabling certificate validation

Delivery:

1. A command-line tool to help users diagnose and repair SSL/TLS problems.
2. A Java library that can be used from other applications to provide users with actionable SSL/TLS diagnostics.

# Building

You need Java in order to build this.

In order to build the `tealess` command line tool, run the following:

```
./gradlew cli:install
```

This will make `tealess` available to you as `./cli/build/install/tealess/bin/tealess`

## Building for distributing

You can build a zip or tar of this project by doing the following:

```
./gradlew cli:distTar

# or, for a .zip file
./gradlew cli:distZip
```

This will put the result in `.cli//build/distributions` as `tealess.zip` or `tealess.tar`

# Design

This library provides an SSLContext that catches any thrown exception and tries to provide a human-readable and actionable report. It does this by wrapping the default SSLContext provided by Java crypto.

Both SSLSocket- and SSLEngine-style usages are supported.

Exception handling is primarily targeted at the SSL/TLS Handshake as this is where most of the problems will happen for users.

## Implementation Details

Because of the somewhat convoluted nature of Java's SSLContext and SSL APIs, most(?) of the code in this repository are object proxies necessary to capture wire data and enrich exceptions. For example, to capture the inbound data of SSLSocket's InputStream, we go SSLContext -> SSLContextSpi -> SSLSocketFactory -> SSLSocket -> SSLSocket.getInputStream() where almost all of the .java files in this path are code-generated proxy classes passing a thing down the stack.

During the handshake, this library writes the wire-bytes into a ByteBuffer for both directions of communication.

* For SSLEngine, see [TealessSSLEngine](https://github.com/elastic/tealess/blob/master/core/src/main/java/co/elastic/tealess/TealessSSLEngine.java#L20-L21).
* For Client Sockets: Tealess's SSLContext.getSocketFactory() returns a [TealessSSLSocketFactory](https://github.com/elastic/tealess/blob/master/core/src/main/java/co/elastic/tealess/TealessSSLSocketFactory.java#L50-L113) which wraps `Socket`s with a [DiagnosticTLSObserver](https://github.com/elastic/tealess/blob/master/core/src/main/java/co/elastic/tealess/DiagnosticTLSObserver.java) which is responsible for capturing input and output wire data as well as catching and diagnosing exceptions.
* :x: For Server Sockets: Tealess's SSLContext.getServerSocketFactory() returns a [TealessSSLServerSocketFactory](https://github.com/elastic/tealess/blob/master/core/src/main/java/co/elastic/tealess/TealessSSLServerSocketFactory.java) which is [not implemented yet](https://github.com/elastic/tealess/blob/master/core/src/main/java/co/elastic/tealess/TealessSSLServerSocket.java)
* For SSL Engine: Tealess's SSLContext.createSSLEngine returns a [TealessSSLEngine](https://github.com/elastic/tealess/blob/master/core/src/main/java/co/elastic/tealess/TealessSSLEngine.java) which captures wire [reads and writes](https://github.com/elastic/tealess/blob/master/core/src/main/java/co/elastic/tealess/TealessSSLEngine.java#L57-L70). [Exceptions](https://github.com/elastic/tealess/blob/master/core/src/main/java/co/elastic/tealess/TealessSSLEngine.java#L154-L157) are enriched with diagnostics.

Exception diagnostic is handled in [DiagnosticTLSObserver](https://github.com/elastic/tealess/blob/master/core/src/main/java/co/elastic/tealess/DiagnosticTLSObserver.java). Wire data is recorded in an in-memory log. This log is examined first for the exception and then backtracked to inspect the network data with the goal of providing an actionable diagnosis for the user.

Exception enrichment is done by creating a new instance of the same (or a close parent in the class heirarchy) with a custom `getMessage()` and copying the underlying `cause`. The goal of this is to have Tealess be a drop-in replacement with no required code changes on the client. Examples of this are [here](https://github.com/elastic/tealess/blob/master/core/src/main/java/co/elastic/tealess/DiagnosticTLSObserver.java#L79-L81) and [here](https://github.com/elastic/tealess/blob/master/core/src/main/java/co/elastic/tealess/DiagnosticTLSObserver.java#L132-L134).

## API Usage

Use the TealessSSLContextBuilder class to create an SSLContext. The TealessSSLContextBuilder class is intended to provide you a single interface for configuring all-things-ssl including cipher suites, trust, keys, etc.

### TealessSSLContextBuidler

```java
TealessSSLContextBuilder cb = new TealessSSLContextBuilder();

// For customizing your trusted certificates
cb.setTrustStore(... /* a KeyStore */);

// For when you need to provide a client certificate (and use its key)
cb.setKeyManagerFactory(... /* a KeyManagerFactory */);

SSLContext ctx = cb.build();

// You can now use `ctx` with any class that takes an SSLContext
// Alternately, for things like Netty, you can use `ctx.createSSLEngine()` to get an SSLEngine from the context.
```

### KeyStoreBuilder

To help make KeyStore classes more approachable, Tealess provides a KeyStoreBuilder class.

```java
KeyStoreBuilder ksb = new KeyStoreBuilder();
// by default, this builder will use the system-wide java keystore (the same as Java's default behavior)

// If you want to wipe any previous things added to this keystore builder:
ksb.empty();

// If you want to explicitly use the default trust store, call:
ksb.useDefaultTrustStore();

// If you want to add a private key and certificate (PEM format):
ksb.addPrivateKeyPEM(keyPath, certificatePath);

// If you want to add a path containing one or more certificates
// The path can be to a file or to a directory.
// If the path is a directory, all files in this directory (non-recursive) are added.
ksb.addCAPath(path)

// If you have a Java KeyStore file you wish to use directly:
ksb.useKeyStore(path, passphrase);
// If you wish to be prompted on the console for the passphrase, omit the passphrase argument:
ksb.useKeyStore(path);
```

There are two outputs of this builder:

* KeyStore: `ksb.buildKeyStore()`
* KeyManagerFactory: `ksb.buildKeyManagerFactory()`

### Example: Client Socket

```
TealessSSLContextBuilder cb = new TealessSSLContextBuilder():
SSLContext ctx = cb.build();

Socket socket = ctx.getSocketFactory().createSocket("google.com", 443);
...
```

Other examples may be found in the unit tests:

* [Demonstration](https://github.com/elastic/tealess/blob/master/core/src/test/java/co/elastic/tealess/Demonstration.java) uses Tealess with [Apache HC's HttpClient](https://hc.apache.org/httpcomponents-client-ga/).
* [SocketWrapperTest](https://github.com/elastic/tealess/blob/master/core/src/test/java/co/elastic/tealess/SocketWrapperTest.java) both Apache HttpClient and `SSLContext.createSocketFactory().createSocket(host, port)`
* [NettyTest](https://github.com/elastic/tealess/blob/master/core/src/test/java/co/elastic/tealess/netty/NettyTest.java) uses Tealess with Netty to make a HTTP request.

