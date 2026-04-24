# Base image with Java for Ghidra
FROM gradle:jdk21

RUN apt-get update && \
    apt-get install -y python3 python3-pip wget unzip file && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.3_build/ghidra_12.0.3_PUBLIC_20260210.zip -O ghidra.zip && \
    unzip ghidra.zip && \
    rm ghidra.zip

ENV GHIDRA_PATH=/opt/ghidra_12.0.3_PUBLIC
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"
ENV JAVA_TOOL_OPTIONS="-Dlog4j.configurationFile=/usr/local/src/custom_log4j.xml"

RUN cd /opt/ghidra_12.0.3_PUBLIC/support/gradle && gradle buildNatives

WORKDIR /usr/local/src
COPY ghidra_scripts/ /usr/local/src/
COPY ghidra_analysis.sh /usr/local/src/ghidra_analysis.sh

RUN chmod +x /usr/local/src/ghidra_analysis.sh

CMD ["/usr/local/src/ghidra_analysis.sh"]
VOLUME /usr/local/src/binaries
VOLUME /host_output
