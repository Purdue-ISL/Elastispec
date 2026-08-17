FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /artifact

COPY translator/requirements.txt /tmp/translator-requirements.txt
RUN python -m pip install --no-cache-dir \
    --extra-index-url https://download.pytorch.org/whl/cpu \
    -r /tmp/translator-requirements.txt

COPY elastispec_llm /artifact/elastispec_llm
COPY config /artifact/config
COPY translator/config /artifact/translator/config
COPY translator/scripts /artifact/translator/scripts
COPY translator/translator_runtime /artifact/translator/translator_runtime

ENTRYPOINT ["python", "translator/scripts/run_translator.py"]
