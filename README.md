**Warning:** This is a prototype and not finished and not very well tested.

# check_hp_msa

Icinga check plugin for HP MSA storages. Inspired by [Zabbix HPMSA Integration](https://github.com/asand3r/zbx-hpmsa).

## Installation

Python 3 is required, and you need the Python [requests](https://pypi.org/project/requests/) module.

Please prefer installation via system packages like `python3-requests`.

Alternatively you can install with pip:

    pip3 install requests

Make sure to modify the shebang to your environment, one of the following should be fine.

    #!/usr/bin/env python3
    #!/usr/bin/python3

Then copy the file to your plugin dir:

    cp check_hp_msa.py /usr/lib*/nagios/plugins/check_hp_msa
    chmod 755 /usr/lib*/nagios/plugins/check_hp_msa

<!--
Also see the [Icinga 2 example command](icinga2/command.conf).
-->

## Usage

```
$ ./check_hp_msa.py --help
...
TODO
```

```
$ ./check_hp_msa.py --api 'https://msa.local' -u icinga -p password --mode disks
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
