FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /artifact

COPY requirements.txt /tmp/auditor-requirements.txt
RUN python -m pip install --no-cache-dir -r /tmp/auditor-requirements.txt

COPY scripts/*.py /artifact/auditor/scripts/

ENTRYPOINT ["python", "/artifact/auditor/scripts/run_auditor.py"]
