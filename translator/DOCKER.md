# Translator Docker

Run commands from the repository root. Gemini is the default and most
extensively tested provider. The image also supports OpenAI; the selected
provider and loader remain controlled by a host-side YAML config.

Install [Docker Engine](https://docs.docker.com/engine/install/) on Linux or
[Docker Desktop](https://docs.docker.com/desktop/) on macOS or Windows before
using the commands below.

## Download The Image

The image is published at
[`qing0/elastispec-translator`](https://hub.docker.com/r/qing0/elastispec-translator).

```bash
docker pull qing0/elastispec-translator:sigcomm2026
```

The image includes Gemini, OpenAI, and the supported LangChain document loaders.

## Prepare Host Files

```bash
mkdir -p configs inputs runs
```

Place the config under `configs/`. If it references local documents, place them
under `inputs/` and use container paths such as
`/artifact/inputs/document.pdf`.

Set `output.run_dir` to the mounted output directory:

```yaml
output:
  run_dir: /artifact/runs
```

## Run With Gemini

```bash
docker run --rm \
  -e GEMINI_API_KEY \
  -v "$PWD/configs:/artifact/configs:ro" \
  -v "$PWD/inputs:/artifact/inputs:ro" \
  -v "$PWD/runs:/artifact/runs" \
  qing0/elastispec-translator:sigcomm2026 \
  --config /artifact/configs/translator.yaml
```

## Run With OpenAI

```bash
docker run --rm \
  -e OPENAI_API_KEY \
  -v "$PWD/configs:/artifact/configs:ro" \
  -v "$PWD/inputs:/artifact/inputs:ro" \
  -v "$PWD/runs:/artifact/runs" \
  qing0/elastispec-translator:sigcomm2026 \
  --config /artifact/configs/translator.yaml
```

Pass only the API key required by the selected config. Do not copy API keys,
host configs, inputs, or outputs into the image.

## Validate A Config

Add `--check-config` after the config path:

```bash
docker run --rm \
  -e GEMINI_API_KEY \
  -v "$PWD/configs:/artifact/configs:ro" \
  -v "$PWD/inputs:/artifact/inputs:ro" \
  qing0/elastispec-translator:sigcomm2026 \
  --config /artifact/configs/translator.yaml \
  --check-config
```

## Logs And Outputs

Container stdout and stderr show run progress. Formal outputs are
`generated_policy.fsl` and `run_metadata.json` under the mounted run directory.
Intermediates and optional debug logs remain under that run's `tmp/` directory.

## Build From Source

To build the same image locally instead of downloading it:

```bash
docker build \
  --platform linux/amd64 \
  -f translator/Dockerfile \
  -t elastispec-translator:local \
  .
```
