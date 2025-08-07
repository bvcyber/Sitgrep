# Use an official Python runtime as a parent image
FROM python:3.12

RUN adduser --disabled-password --gecos '' sitgrep

RUN mkdir /sitgrep
RUN mkdir /sitgrep/static
RUN mkdir /sitgrep/static/js
RUN mkdir /sitgrep/static/css
RUN mkdir /sitgrep/static/img
RUN mkdir /sitgrep/reports

COPY ./src/docker/static/js /sitgrep/static/js
COPY ./src/docker/static/css /sitgrep/static/css
COPY ./src/docker/static/img /sitgrep/static/img
COPY ./src/docker/main.py /sitgrep/
COPY ./src/docker/templates /sitgrep/templates

RUN chown -R sitgrep:sitgrep /sitgrep

WORKDIR /install
COPY . /install
ENV PYTHONPATH=/install/src:$PYTHONPATH
RUN chown -R sitgrep:sitgrep /install
USER sitgrep
ENV PATH="/home/sitgrep/.local/bin:${PATH}"
RUN pip install Flask
RUN pip install GitPython>=3.1.43
RUN pip install rich
RUN pip install PyYAML
RUN python install.py

WORKDIR /sitgrep
EXPOSE 8000

RUN sitgrep sources fetch
CMD ["python", "/sitgrep/main.py"]