
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
