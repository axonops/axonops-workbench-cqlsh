# AxonOps Workbench cqlsh project
The associated project [AxonOps Workbench](https://axonops.com/workbench/) for Apache Cassandra® (https://github.com/axonops/axonops-workbench) uses to build CQLSH for internal use within the application

## Acknowledgements

This project is a fork of the `cqlsh` utility, originally developed as part of the Apache Cassandra project. We extend our sincere gratitude to the Apache Cassandra community for their outstanding work.

Apache Cassandra is a free and open-source, distributed, wide-column store, NoSQL database management system designed to handle large amounts of data across many commodity servers, providing high availability with no single point of failure.

### Apache Cassandra Resources

- **Official Website**: [cassandra.apache.org](https://cassandra.apache.org/)
- **Source Code**: Available on [GitHub](https://github.com/apache/cassandra) or the primary Apache Git repository at `gitbox.apache.org/repos/asf/cassandra.git`
- **Documentation**: Comprehensive guides and references available at the [Apache Cassandra website](https://cassandra.apache.org/)

This fork maintains the spirit of the original project while adding specific functionality for our use case. We encourage users to explore and contribute to the main Apache Cassandra project.

## Software Bill of Materials (SBOM)

This project provides Software Bill of Materials (SBOM) files with each release, offering transparency into our software components and dependencies. SBOMs help users and organizations understand exactly what components are included in our software, enabling better security and compliance management.

**Available SBOM Formats**
- CycloneDX (sbom.cyclonedx.json): A lightweight SBOM standard that provides detailed component information and security context
- SPDX (sbom.spdx.json): A comprehensive format focusing on software licensing and component identification

**Benefits of Our SBOM**
- Security: Easily identify and track known vulnerabilities in dependencies
- Compliance: Verify license obligations for all included components
- Transparency: Clear visibility into the software supply chain
- Risk Management: Better understand and assess potential risks in the software stack

You can find our SBOM files in each [release](releases) as part of the release artifacts. These files are automatically generated during our build process to ensure they remain current with each release.

**Using SBOM Files**
- Download the SBOM file in your preferred format from the release assets
- Use SBOM analysis tools like:
  - `cyclonedx-cli` for CycloneDX files
  - `spdx-tools` for SPDX files
- Integrate with your security and compliance workflows
- Monitor for vulnerabilities in included components

We maintain these SBOM files as part of our commitment to software supply chain security and transparency. They are updated with each release to reflect the current state of our software dependencies.

***

*This project may contain trademarks or logos for projects, products, or services. Any use of third-party trademarks or logos are subject to those third-party's policies. AxonOps is a registered trademark of AxonOps Limited. Apache, Apache Cassandra, Cassandra, Apache Spark, Spark, Apache TinkerPop, TinkerPop, Apache Kafka and Kafka are either registered trademarks or trademarks of the Apache Software Foundation or its subsidiaries in Canada, the United States and/or other countries. Elasticsearch is a trademark of Elasticsearch B.V., registered in the U.S. and in other countries. Docker is a trademark or registered trademark of Docker, Inc. in the United States and/or other countries.*
