# WireGuard Support

To use the WireGuard protocol with ProtonVPN or any other provider, you must have `wireguard.exe` installed on your system. This executable is required for connecting and disconnecting WireGuard tunnels from the application.

- Download WireGuard for Windows: https://www.wireguard.com/install/
- Ensure `wireguard.exe` is available in your system PATH or in the default installation directory.

If `wireguard.exe` is not installed, WireGuard connections will fail and you will not be able to use this protocol in the app.

**Important:** ProtonVPN WireGuard config files expire every 2 hours. You must download a fresh `.conf` file from the ProtonVPN website or app before connecting. If you use an expired config, connection will fail or disconnect unexpectedly.
