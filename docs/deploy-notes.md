# GateRelay Deploy Notes

GateRelay can be built on one machine and copied to the production server. It does not require Docker or external runtime services.

1. Build the binary on a machine with Go installed:

   ```sh
   go build -o gaterelay ./cmd/gaterelay
   ```

2. Create a dedicated service user if it does not already exist:

   ```sh
   sudo useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin gaterelay
   ```

3. Install the binary and config:

   ```sh
   sudo install -m 0755 gaterelay /usr/local/bin/gaterelay
   sudo install -d -m 0750 -o root -g gaterelay /etc/gaterelay
   sudo install -m 0640 -o root -g gaterelay configs/production.example.yaml /etc/gaterelay/config.yaml
   ```

4. Edit `/etc/gaterelay/config.yaml` and set the proxy URL, username, and password for your environment.

5. Make sure `tls.cert_file` and `tls.key_file` point to certificate files for the configured public domain, and make sure the `gaterelay` service user can read them.

6. Validate the config before starting:

   ```sh
   /usr/local/bin/gaterelay -config /etc/gaterelay/config.yaml -check-config
   ```

7. Install and start the systemd unit:

   ```sh
   sudo install -m 0644 deploy/gaterelay.service /etc/systemd/system/gaterelay.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now gaterelay
   ```

GateRelay reads proxy credentials only from the config file. Do not put proxy credentials in the systemd unit or command line.
