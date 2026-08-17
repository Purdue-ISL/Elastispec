# Elastispec

Elastispec aids operators in auditing enterprise firewall configurations against
policies expressed in vendor documentation. Enterprises run many applications,
including print management, backup, monitoring, authentication, and other vendor
systems. Each application is associated with vendor documents that describe which
traffic should be allowed, while the enterprise network contains concrete
firewall rules, inventories, and application deployments. Elastispec bridges
these sources so operators can check whether the firewall configuration matches
the documented application requirements.

This is based on a paper published at ACM SIGCOMM 2026.

## Citation

If you use this code, please cite:

```bibtex
@inproceedings{10.1145/3789240.3829191,
author = {Wen, Chenan and Qing, Yizhan and Jansen, Curt P and Qiu, Xiaokang and Rao, Sanjay G},
title = {Elastispec: Formalizing Enterprise Firewall Management with Informal and Elastic Specifications},
year = {2026},
isbn = {9798400724671},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3789240.3829191},
doi = {10.1145/3789240.3829191},
booktitle = {Proceedings of the ACM SIGCOMM 2026 Conference},
pages = {140–159},
numpages = {20},
keywords = {enterprise firewalls, network verification, domain-specific languages, LLM agents, configuration auditing},
location = {Colorado Convention Center, Denver, CO, USA},
series = {SIGCOMM '26}}
```

Elastispec has two major components:

- The [Translator](translator/README.md) converts vendor application
  documentation into a candidate Elastispec specification. The operator reviews
  and corrects the specification before auditing.
- The [Auditor](auditor/README.md) checks a firewall configuration against a
  reviewed specification and an entity-to-IP inventory, then produces a
  compliance report.

The usual workflow is to run the Translator, review its candidate specification,
and then run the Auditor. When a reviewed specification is already available,
you can start directly with the Auditor.

## Start Here

We recommend starting with the [Auditor](auditor/README.md). Its quick start
includes a simplified [PaperCut](https://www.papercut.com/) example with all
required sample inputs. The Auditor README covers setup, inventory preparation,
running the audit, and reading the compliance report.

Pre-created specifications and inventory templates are available under
[`auditor/specifications/`](auditor/specifications/).

Use the [Translator](translator/README.md) when a reviewed specification is not
available for an application. Its README covers installation, document inputs,
LLM provider configuration, and source and Docker usage.

## LLM Usage

The Translator uses an LLM; the Auditor does not. Users can select the LLM
provider and model and adjust supported settings in the YAML configuration. See
the [Translator README](translator/README.md) and
[configuration guide](translator/CONFIGURATION.md) for provider setup,
parameters, API keys, and usage considerations.

Only vendor documentation is sent to an LLM provider; all other inputs,
including firewall configurations, remain local.

Please contact `qing0@purdue.edu` for any questions.

This artifact is released under the MIT License. See [`LICENSE`](LICENSE).
