FROM python:3.11-slim

LABEL maintainer="ReconX"
LABEL description="Automated Reconnaissance & Vulnerability Scanner"

# Install nikto (optional) and basic tools
RUN apt-get update && apt-get install -y \
    dnsutils curl wget perl libnet-ssleay-perl \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/sullo/nikto/archive/master.tar.gz -O /tmp/nikto.tar.gz && \
    tar -xzf /tmp/nikto.tar.gz -C /opt/ && \
    ln -s /opt/nikto-master/program/nikto.pl /usr/local/bin/nikto && \
    rm /tmp/nikto.tar.gz || true

# Install nuclei (optional)
RUN ARCH=$(dpkg --print-architecture) && \
    NUCLEI_VERSION="3.2.4" && \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip" \
         -O /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip nuclei -d /usr/local/bin/ && \
    rm /tmp/nuclei.zip || true   # non-fatal: nuclei is optional

WORKDIR /app
COPY . .

RUN chmod +x main.py
RUN mkdir -p reports output

ENTRYPOINT ["python3", "main.py"]
CMD ["--help"]
