FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      gnome-keyring gcr dbus dbus-x11 xvfb xdotool x11-utils imagemagick fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m tester
USER tester
