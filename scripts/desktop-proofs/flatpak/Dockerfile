FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      flatpak xdg-desktop-portal gnome-keyring dbus ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m tester
USER tester
RUN flatpak remote-add --user flathub https://dl.flathub.org/repo/flathub.flatpakrepo \
 && flatpak install --user -y --noninteractive flathub org.freedesktop.Platform//24.08
