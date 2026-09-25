FROM python:3.12-slim

# ping is used to check every ISP link
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the project, then keep only what the app needs.
# Images for the pages (e.g. network-monitor-plain.svg) can be in a static/ folder
# or next to isp-monitor.py; both end up in /app/static.
COPY . /src/
RUN cp /src/isp-monitor.py /src/dashboard.html /src/login.html /src/reset-password.html /app/ \
 && mkdir -p /app/static \
 && if [ -d /src/static ]; then cp -r /src/static/. /app/static/; fi \
 && for f in /src/*.svg /src/*.png /src/*.jpg /src/*.jpeg /src/*.gif /src/*.webp /src/*.ico; do \
      [ -f "$f" ] && cp "$f" /app/static/ || true; done \
 && rm -rf /src

# The app saves sites_data.json and future_sites_data.json next to isp-monitor.py.
# Point them into /app/data so they are stored on the persistent volume.
RUN mkdir -p /app/data /app/uploads \
 && ln -sf /app/data/sites_data.json /app/sites_data.json \
 && ln -sf /app/data/future_sites_data.json /app/future_sites_data.json \
 && python -m py_compile /app/isp-monitor.py

EXPOSE 3000
CMD ["python", "isp-monitor.py"]
