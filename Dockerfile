# Use an official Python runtime as a parent image
FROM python:3.12

RUN adduser --disabled-password --gecos '' sitgrep

RUN mkdir -p /sitgrep/static/js /sitgrep/static/css /sitgrep/static/img /sitgrep/reports /install \
    && chown -R sitgrep:sitgrep /sitgrep /install

COPY --chown=sitgrep:sitgrep ./src/docker/static/js /sitgrep/static/js
COPY --chown=sitgrep:sitgrep ./src/docker/static/css /sitgrep/static/css
COPY --chown=sitgrep:sitgrep ./src/docker/static/img /sitgrep/static/img
COPY --chown=sitgrep:sitgrep ./src/docker/main.py /sitgrep/
COPY --chown=sitgrep:sitgrep ./src/docker/templates /sitgrep/templates

WORKDIR /install
ENV PYTHONPATH=/install/src
ENV PIP_NO_CACHE_DIR=1
USER sitgrep
ENV PATH="/home/sitgrep/.local/bin:${PATH}"

# Install dependencies from an empty package stub first so this layer is only
# rebuilt when pyproject.toml changes, not on every source edit.
COPY --chown=sitgrep:sitgrep pyproject.toml README.md ./
RUN mkdir src && touch src/__init__.py \
    && pip install ".[web]" \
    && rm -rf src build

COPY --chown=sitgrep:sitgrep . .
RUN python install.py

WORKDIR /sitgrep
EXPOSE 9000

RUN sitgrep sources fetch
CMD ["python", "/sitgrep/main.py"]
