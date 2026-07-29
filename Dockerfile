FROM python:3.12-alpine
LABEL org.opencontainers.image.title="VPS Sentinel" \
      org.opencontainers.image.description="Low-overhead VPS disk I/O, CPU and memory incident monitor"
RUN apk add --no-cache procps iproute2 sysstat util-linux coreutils docker-cli
WORKDIR /app
COPY vps_monitor.py /app/vps_monitor.py
RUN chmod 0555 /app/vps_monitor.py && mkdir -p /data && python3 -m py_compile /app/vps_monitor.py
ENV MONITOR_DATA_DIR=/data PYTHONUNBUFFERED=1
ENTRYPOINT ["python3","/app/vps_monitor.py"]
CMD ["run"]
