# Translator Configuration

This file is the detailed YAML configuration reference. For the shortest path
to a working Gemini run, start with [`README.md`](README.md).

A configuration makes two main choices: the LLM provider and the document-input
path. Gemini is the default and most extensively tested provider. LangChain is
the recommended document loader.

## Top-Level Sections

```yaml
app:
  name: ExampleApp

provider:
  kind: gemini
  model: gemini-3.1-pro-preview
  api_key_env: GEMINI_API_KEY

loader:
  kind: langchain
  sources:
    - https://example.com/vendor-documentation

output:
  run_dir: runs/example
```

The common sections are `app`, `provider`, `loader`, and `output`. Optional
sections include `operation_overrides`, `retry`, `logging`, `save`, and `cost`.

Optional generation parameters are not sent unless they are explicitly present
in the config. The default config therefore does not set `temperature`,
output-token limits, or reasoning/thinking parameters; provider defaults apply.

Fields under `provider.generation_config` are forwarded to the selected provider
SDK. The workflow rejects keys that it owns itself: `format`, `input`,
`messages`, `model`, `prompt`, `response_schema`, `response_modalities`,
`stream`, `tools`, `text`, `response_json_schema`, `response_mime_type`,
`response_format`, and `web_search_options`. Refer to the
[Google Gen AI SDK configuration reference](https://googleapis.github.io/python-genai/index.html)
or the [OpenAI API reference](https://platform.openai.com/docs/api-reference/responses/create)
for the complete provider-specific fields and value types accepted by the
installed SDK version.

## Choose An LLM Provider

Keep API keys in environment variables rather than YAML files or Docker images:

| Provider | macOS/Linux | PowerShell |
| --- | --- | --- |
| Gemini | `export GEMINI_API_KEY=YOUR_KEY` | `$env:GEMINI_API_KEY = "YOUR_KEY"` |
| OpenAI | `export OPENAI_API_KEY=YOUR_KEY` | `$env:OPENAI_API_KEY = "YOUR_KEY"` |

### Gemini

Gemini is the default provider and the recommended starting point.

```yaml
provider:
  kind: gemini
  model: gemini-3.1-pro-preview
  api_key_env: GEMINI_API_KEY
  web_search:
    enabled: true
  generation_config:
    thinking_config:
      thinking_level: high
```

Fields under `generation_config` are passed to
`google.genai.types.GenerateContentConfig`. Nested values such as
`thinking_config` use the Google Gen AI SDK shape. The Translator converts a
string `thinking_level` to the SDK enum.

Gemini Google Search accepts optional fields under
`web_search.google_search`:

```yaml
web_search:
  enabled: true
  google_search:
    exclude_domains:
      - example.net
```

Supported Google Search fields are `search_types`, `blocking_confidence`,
`exclude_domains`, and `time_range_filter`.

### OpenAI

OpenAI is supported but has been less extensively tested and tuned than Gemini,
so model-specific tuning may be needed.

```yaml
provider:
  kind: openai
  model: gpt-5
  api_key_env: OPENAI_API_KEY
  api_mode: responses
  web_search:
    enabled: true
  generation_config:
    reasoning:
      effort: high
```

`api_mode` may be:

- `responses` (default): uses the Responses API and supports web search.
- `chat_completions`: uses Chat Completions; workflow web search must be off.

`generation_config` is forwarded to the selected OpenAI API method. For the
Responses API, optional web-search tool fields may be placed directly under
`web_search`:

```yaml
web_search:
  enabled: true
  search_context_size: medium
```

Supported tool fields are `type`, `search_context_size`, `filters`,
`user_location`, `external_web_access`, and `return_token_budget`.

## Choose A Document Input

### LangChain

The default LangChain configuration accepts URLs and local file paths and
automatically detects supported formats, including PDF, Office documents, HTML,
Markdown, and images. A single `sources` list may contain different supported
formats.

```yaml
loader:
  kind: langchain
  sources:
    - https://example.com/vendor-documentation
    - /absolute/path/to/vendor-manual.pdf
```

This concise form defaults to whole-document Markdown, so each source is passed
to the Translator as one complete document. A document type does not need to be
specified.

Optional constructor settings may be passed under `kwargs`; `file_path` is
reserved because it is derived from `sources`:

```yaml
loader:
  kind: langchain
  sources:
    - /absolute/path/to/vendor-manual.pdf
  kwargs:
    convert_kwargs:
      max_num_pages: 200
```

Start from [`gemini_langchain.yaml`](config/examples/gemini_langchain.yaml). For
the default loader's supported formats and advanced options, see its
[LangChain loader reference](https://docs.langchain.com/oss/python/integrations/document_loaders/docling).

### Choose A Specific LangChain Loader

The generic LangChain path remains available for compatibility with earlier
experiments and for loaders with source-specific behavior:

#### WebBaseLoader

```yaml
loader:
  kind: langchain
  class_path: langchain_community.document_loaders.WebBaseLoader
  args: []
  kwargs:
    web_paths:
      - https://example.com/vendor-documentation
    raise_for_status: true
  method: load
```

`class_path` names an importable loader class. `args` and `kwargs` are passed
directly to its constructor. `method` defaults to `load`; use another method
such as `lazy_load` only when it returns documents or an iterable of documents.
Start from [`gemini_web.yaml`](config/examples/gemini_web.yaml) for the
`WebBaseLoader` configuration used by earlier experiments.

#### PyPDFLoader

Use `PyPDFLoader` when you want the conventional text-based PDF loader instead
of automatic format detection or Gemini native PDF:

```yaml
loader:
  kind: langchain
  class_path: langchain_community.document_loaders.PyPDFLoader
  kwargs:
    file_path: /absolute/path/to/vendor-manual.pdf
    mode: single
```

`mode: single` passes the complete PDF to the Translator as one document. The
standard Translator requirements include the `pypdf` dependency. Other
LangChain loaders use the same `class_path`, `args`, `kwargs`, and optional
`method` structure.

### Gemini Native PDF

For PDF inputs, Gemini native PDF is recommended when the selected Gemini model
supports multimodal/native PDF processing, such as Gemini 3.1 Pro. The
recommended LangChain path remains available when native processing is
unavailable or not preferred, including with an earlier or lower-cost model
that lacks this capability.

```yaml
loader:
  kind: gemini_native_pdf
  local_paths:
    - /absolute/path/to/document.pdf
```

The PDFs are uploaded through the Gemini Files API and attached directly to the
document-processing requests. The top-level provider and every operation
override must use Gemini. Start from
[`gemini_native_pdf.yaml`](config/examples/gemini_native_pdf.yaml).

### Inline Text

Inline text is intended for small examples and smoke tests rather than normal
document runs:

```yaml
loader:
  kind: inline_text
  documents:
    - Small public example input
```

## Per-Operation Overrides

The top-level provider is used for every operation by default. Override only the
operations that need a different provider, model, or provider configuration:

```yaml
operation_overrides:
  generate_outline:
    provider:
      kind: openai
      model: gpt-5
      api_key_env: OPENAI_API_KEY
      api_mode: responses
      web_search:
        enabled: true

  determine_optionality:
    provider:
      kind: gemini
      model: gemini-2.5-pro
      api_key_env: GEMINI_API_KEY
```

Supported operation IDs are:

```text
generate_outline
extract_section_content
extract_policies
generate_leaf_specs
reconcile_coupled_leaves
assemble_hierarchy
correct_hierarchy_json
determine_optionality
```

Overrides may change between Gemini and OpenAI. An override is merged with the
top-level provider when the provider kind stays the same. When the kind changes,
set the target model and API-key environment explicitly. Cross-provider
overrides cannot be used with Gemini native PDF.

## Runtime And Output Settings

These settings normally do not need to be changed for a first run.

### Output

```yaml
output:
  run_dir: runs/example
```

The application name is appended automatically, producing
`runs/example/<app.name>/`.

### Retry

```yaml
retry:
  enabled: true
  max_attempts: 3
  initial_backoff_seconds: 2
  max_backoff_seconds: 30
  backoff_multiplier: 2
  jitter: true
```

Retry applies to transient provider and network failures. Validation and config
errors fail immediately.

### Logging And Saved Content

```yaml
logging:
  events_jsonl: true
  include_error_messages: false
  print_run_progress: true

save:
  prompts: false
  llm_responses: false
```

Runtime events are stored under `tmp/events.jsonl`. Prompt and raw-response
logging is disabled by default. If enabled, files are stored under
`tmp/llm_debug/` and may contain supplied document content.

### Cost

```yaml
cost:
  pricing_path: config/pricing.example.yaml
```

Token counts come from provider responses. Cost is an estimate based on the
selected pricing file; verify current provider rates before relying on it.
