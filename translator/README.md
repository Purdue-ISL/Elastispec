# Elastispec Translator

The Translator generates candidate Elastispec DSL specifications from vendor
application documentation. The operator must review and correct the generated
specification before passing it to the Auditor.

Gemini is the default provider and is the provider on which the Translator has
been most extensively tested and tuned. OpenAI is also supported; see
[Other Provider Support](#other-provider-support).

Only vendor documentation is sent to an LLM provider; all other inputs,
including firewall configurations, remain local.

## Quick Start With Gemini

Run commands from the repository root.

```bash
python3 -m venv translator/.venv
source translator/.venv/bin/activate
python -m pip install -r translator/requirements.txt
```

Start with the recommended Gemini and LangChain example:

```bash
cp translator/config/examples/gemini_langchain.yaml /tmp/translator.yaml
```

Edit `app.name` and the document sources in `/tmp/translator.yaml`, then set the
Gemini API key:

```bash
export GEMINI_API_KEY=YOUR_KEY
```

Validate the configuration without calling Gemini:

```bash
python translator/scripts/run_translator.py \
  --config /tmp/translator.yaml \
  --check-config
```

Run the Translator:

```bash
python translator/scripts/run_translator.py \
  --config /tmp/translator.yaml
```

The results are written under `<output.run_dir>/<app.name>/`.

## Creating Your Configuration

A Translator configuration makes two main choices: the LLM provider and the
document input. Gemini is the default provider, and LangChain is the recommended
document loader.

The common top-level sections are:

| Section | Purpose |
| --- | --- |
| `app` | Names the application being translated. |
| `provider` | Selects the LLM provider and model. |
| `loader` | Selects how the vendor documentation is loaded. |
| `output` | Selects the run directory. |

The example configs intentionally contain only the settings needed to start a
run. Provider parameters, loader constructor arguments, per-operation
overrides, retry, logging, and cost settings are documented in
[`CONFIGURATION.md`](CONFIGURATION.md).

### Choose The Document Input

The recommended LangChain configuration accepts URLs or local file paths under
`loader.sources` and automatically detects supported formats, including PDF,
Office documents, HTML, Markdown, and images. Existing `WebBaseLoader` configs
and other installed LangChain loaders remain supported.

For PDF inputs, we recommend Gemini native PDF when the selected Gemini model
supports multimodal/native PDF processing, such as Gemini 3.1 Pro. When native
processing is unavailable, including with an earlier or lower-cost model that
lacks this capability, use the default LangChain path.

| Example config | Use |
| --- | --- |
| [`gemini_langchain.yaml`](config/examples/gemini_langchain.yaml) | Recommended path for URLs and local documents; the supported format is detected automatically. |
| [`gemini_web.yaml`](config/examples/gemini_web.yaml) | Website input through `WebBaseLoader`, retained for compatibility with earlier experiments. |
| [`gemini_native_pdf.yaml`](config/examples/gemini_native_pdf.yaml) | PDF passed directly to a compatible Gemini model; recommended when available. |

Detailed provider and loader settings, including other LangChain loaders and
inline text, are in [`CONFIGURATION.md`](CONFIGURATION.md).

## Outputs

The formal outputs are:

- `generated_policy.fsl`: candidate Elastispec specification for operator
  review.
- `run_metadata.json`: provider plan, token usage, elapsed time, estimated cost,
  retry summary, and output paths.

Intermediates are stored under `tmp/` inside the run directory. They preserve
completed stages for resume and debugging after an interrupted run; they are not
formal outputs. Runtime events are stored in `tmp/events.jsonl`. Prompt and raw
LLM response logging is disabled by default because those files may contain the
supplied document content.

## Docker And CLI

For Docker instructions, see [`DOCKER.md`](DOCKER.md).

| Argument | Purpose |
| --- | --- |
| `--config PATH` | Run with the specified YAML configuration. |
| `--app NAME` | Override `app.name` for one run. |
| `--check-config` | Validate the configuration without calling an LLM. |
| `--progress` | Print cumulative token and estimated cost information. |

## Other Provider Support

OpenAI is supported, but the Translator has been less extensively tested and
tuned with OpenAI models, so model-specific tuning may be needed. Set
`OPENAI_API_KEY` in the environment and follow the
[OpenAI configuration reference](CONFIGURATION.md#openai).

Local-model support is planned for a future release.
