# Azure Key Vault Provider

[![Build Status](https://travis-ci.org/hmcts/azure-keyvault-jca-provider.svg?branch=master)](https://travis-ci.org/hmcts/azure-keyvault-jca-provider)
[![codecov](https://codecov.io/gh/hmcts/azure-keyvault-jca-provider/branch/master/graph/badge.svg)](https://codecov.io/gh/hmcts/azure-keyvault-jca-provider)

This project provides a [JCA Provider](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#Provider)
for operations on Azure's [Key Vault](https://azure.microsoft.com/en-us/services/key-vault/) service.

## Getting Started

### Prerequisites

- [Java 8](https://www.oracle.com/java)

### Building

The project uses [Gradle](https://gradle.org) as a build tool but you don't have install it locally since there is a
`./gradlew` wrapper script.

To build project please execute the following command:

```bash
$ ./gradlew build
```

## Developing

### Unit tests

To run all unit tests please execute the following command:

```bash
$ ./gradlew test
```

## Versioning

We use [SemVer](http://semver.org/) for versioning.
For the versions available, see the tags on this repository.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
