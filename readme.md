# pades-validator

This is a simple tool for validating signed PDF files.

##### Compiling

```mvn compile```

##### Running

```mvn exec:java -Dexec.mainClass="fi.methics.validator.pades.PAdESValidator" -Dexec.args="-pdf=example.pdf -jks=truststore.jks"```

##### Usage

```
Usage: fi.methics.validator.pades.PAdESValidator [OPTIONS]

Options:
  -signed=               - PAdES signed file path
  -jks=VALUE             - optional path to truststore file
  -jkspwd=VALUE          - optional truststore password

Example:
  java fi.methics.validator.pades.PAdESValidator -pdf=C:\tmp\example.pdf
```
