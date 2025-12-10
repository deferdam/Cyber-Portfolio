#!/usr/bin/env bash
set -euo pipefail

# install_jenkins.sh
# Automates Jenkins installation on Fedora 42.
# Usage: chmod +x install_jenkins.sh && sudo ./install_jenkins.sh [--unsafe-no-gpgcheck]

JENKINS_REPO_URL="https://pkg.jenkins.io/redhat-stable/"
JENKINS_GPG_URL="https://pkg.jenkins.io/redhat-stable/jenkins.io.key"
REPO_FILE="/etc/yum.repos.d/jenkins.repo"
KEY_FILE="/etc/pki/rpm-gpg/jenkins.io.key"
SKIP_GPG_CHECK=0

show_help() {
  cat <<EOF
[SECUR VAULT PROJECT - JENKINS INSTALLER FOR FEDORA 42]

Usage: sudo ./install_jenkins.sh [OPTIONS]

Options:
  --unsafe-no-gpgcheck   Install Jenkins with GPG check disabled (Not recomanded).
  -h, --help             Show this help message.

This script will:
 - install OpenJDK 21
 - create the Jenkins yum repo with gpgkey
 - download and import the Jenkins GPG key
 - install Jenkins
 - enable and start the Jenkins service
 - open port 8080 in firewalld (if available)

Run as root or with sudo.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --unsafe-no-gpgcheck)
      SKIP_GPG_CHECK=1
      shift
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      show_help
      exit 1
      ;;
  esac
done

if [[ $(id -u) -ne 0 ]]; then
  echo "This script must be run as root. Use sudo." >&2
  exit 2
fi

command -v dnf >/dev/null 2>&1 || { echo "dnf not found" >&2; exit 3; }
command -v curl >/dev/null 2>&1 || { echo "curl not found => Installing curl..."; dnf install -y curl; }
command -v rpm >/dev/null 2>&1 || { echo "rpm not found => Aborting." >&2; exit 4; }

echo "==> Installing OpenJDK 21"
dnf install -y java-21-openjdk

echo "==> Creating Jenkins repo file at $REPO_FILE"
cat > "$REPO_FILE" <<EOF
[jenkins]
name=Jenkins-stable
baseurl=$JENKINS_REPO_URL
gpgcheck=1
repo_gpgcheck=1
gpgkey=$JENKINS_GPG_URL
enabled=1
EOF

echo "==> Downloading Jenkins GPG key to $KEY_FILE"
if curl -fsSL -o "$KEY_FILE" "$JENKINS_GPG_URL"; then
  echo "GPG key downloaded. Importing into RPM keyring..."
  if rpm --import "$KEY_FILE"; then
    echo "Key imported into RPM.";
  else
    echo "Warning: rpm --import failed. Continuing to make cache (may still work).";
  fi
else
  echo "Failed to download GPG key from $JENKINS_GPG_URL" >&2
  if [[ $SKIP_GPG_CHECK -eq 0 ]]; then
    echo "You can retry or run with --unsafe-no-gpgcheck to bypass GPG verification." >&2
    exit 5
  fi
fi

echo "==> Refreshing dnf cache"
dnf clean all || true
dnf makecache --refresh || true

INSTALL_CMD=(dnf install -y jenkins)
if [[ $SKIP_GPG_CHECK -eq 1 ]]; then
  echo "WARNING: GPG checks will be skipped for this installation (unsafe)."
  INSTALL_CMD=(dnf install --nogpgcheck -y jenkins)
fi

echo "==> Installing Jenkins"
if "${INSTALL_CMD[@]}"; then
  echo "Jenkins package installed."
else
  echo "Package installation failed" >&2
  dnf -v install -y jenkins || true
  echo "If you see GPG signature errors, ensure the key at $KEY_FILE matches the upstream key." >&2
  exit 6
fi

echo "==> Enabling and starting Jenkins service"
systemctl enable --now jenkins

if command -v firewall-cmd >/dev/null 2>&1; then
  echo "==> Opening port 8080 in firewalld"
  firewall-cmd --permanent --add-port=8080/tcp || true
  firewall-cmd --reload || true
else
  echo "firewall-cmd not found; skipping firewall configuration."
fi

sleep 3

PASSWORD_FILE="/var/lib/jenkins/secrets/initialAdminPassword"
if [[ -f "$PASSWORD_FILE" ]]; then
  echo "==> Initial admin password (also at $PASSWORD_FILE):"
  cat "$PASSWORD_FILE"
else
  echo "==> initialAdminPassword not found yet at $PASSWORD_FILE. It may appear after Jenkins finishes its first startup iterations."
fi

cat <<EOF

Jenkins should now be installed and running.
 - Open: http://<your-host>:8080
 - If the initial admin password didn't display above, check: sudo cat $PASSWORD_FILE

Notes:
 - Prefer importing the GPG key and using normal install; --unsafe-no-gpgcheck was provided only as a fallback.
 - For production, consider configuring HTTPS (nginx reverse proxy + certbot) and creating separate build agents.

EOF

exit 0
