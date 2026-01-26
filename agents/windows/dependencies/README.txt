Place the Npcap installer in this folder for unattended setup.

Expected filename:
  npcap-installer.exe
Optional filename:
  vc_redist.x64.exe

How it is used:
  bootstrap-install.ps1 automatically checks this path:
    .\dependencies\npcap-installer.exe
  If Npcap is missing, it runs the installer silently.
  For VC++ runtime, it checks:
    .\dependencies\vc_redist.x64.exe
  If missing, bootstrap attempts Microsoft download as fallback.

Notes:
  - Use a trusted installer from https://npcap.com/
  - Keep this file in deployment bundles for enterprise/offline installs.
