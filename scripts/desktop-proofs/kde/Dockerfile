FROM fedora:41
RUN dnf -y -q install kf6-kwallet xorg-x11-server-Xvfb xdotool dbus-daemon dbus-tools ImageMagick dejavu-sans-fonts procps-ng \
 && dnf clean all
RUN useradd -m tester
USER tester
