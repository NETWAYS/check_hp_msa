**Warning:** This is a prototype and not finished and not very well tested.

# check_hp_msa

Icinga check plugin for HP MSA storages. Inspired by [Zabbix HPMSA Integration](https://github.com/asand3r/zbx-hpmsa).

## Installation

The plugin requires at least Python 3.

Python dependencies:

* `requests`

Please prefer installation via system packages like `python3-requests`.

Alternatively you can install with pip:

    pip3 install requests

Make sure to modify the shebang to your environment, one of the following should be fine:

    #!/usr/bin/env python3
    #!/usr/bin/python3

Then copy the file to your plugin dir:

    cp check_hp_msa.py /usr/lib*/nagios/plugins/check_hp_msa
    chmod 755 /usr/lib*/nagios/plugins/check_hp_msa

## Usage

```bash
check_hp_msa.py --help

-h, --help            show this help message and exit
--api API, -A API     HP MSA host url (e.g. https://msa1.local)
--username USERNAME, -u USERNAME
                      Username for login (CHECK_HP_MSA_API_USER)
--password PASSWORD, -p PASSWORD
                      Password for login (CHECK_HP_MSA_API_PASSWORD)
--mode MODE, -m MODE  Check mode
--insecure            Do not check certificates
--version, -V         Print version
--auth-hash-type {md5,sha256}
                      The Hash algorithm to use for the authentication procedure
```

Various flags can be set with environment variables, refer to the help to see which flags.

## Example

```bash
check_hp_msa.py --api 'https://msa.local' -u icinga -p password --mode disks
[OK] 82 disks

[1.1 ] SEAGATE ST10000NM002G 10.0TB SERIALNO Up OK
[1.2 ] SEAGATE ST10000NM002G 10.0TB SERIALNO Up OK
[1.3 ] SEAGATE ST10000NM002G 10.0TB SERIALNO Up OK
[1.4 ] SEAGATE ST10000NM002G 10.0TB SERIALNO Up OK
[1.5 ] SEAGATE ST10000NM002G 10.0TB SERIALNO Up OK
...
```

## API Documentation

See the chapter "Using the XML API" in [HP MSA 2040CLI Reference Guide](https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-c03791989).

## License

HP MSA and its variants are a trademark of Hewlett-Packard Development Company, L.P.

Copyright (C) 2021 [NETWAYS GmbH](mailto:info@netways.de)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
