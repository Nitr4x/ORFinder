# ORFinder

#Purpose

ORFinder allows scanning the internet to find SMTP services vulnerable to open relay attack.

# Build

To build the container, just use this command:

```bash
docker build -t orfinder .
```

Docker will download the Debian image and then execute the installation steps.

> Be patient, the process can be quite long the first time.

# Run

Once the build process is over, get and enjoy your new open relay scanner !

```bash
docker run -it --rm orfinder -c COUNTRY_CODE
```

> Note: Don't forget to regularly pull this repository for updates.

# Disclaimer

The author of this tool is not responsible for misuse or for any damage that you may cause!
You agree that you use this software at your own risk.
