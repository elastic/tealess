
![tealess](tealess.png)

----

NOTE: This project is not yet ready for general use. We're still figuring out
what we want it to do and what interfaces it should provide for users.

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

## Design

This library provides an SSLContext that catches any thrown exception and tries to provide a human-readable and actionable report. It does this by wrapping the default SSLContext provided by Java crypto.

Exception handling is primarily targeted at the SSL/TLS Handshake as this is where most of the problems will happen for users.

When an exception is thrown

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
