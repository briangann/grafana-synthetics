# grafana-synthetics

## Prerequisites

```
pip install -r requirements.txt
```

## Hosted Graphite with CRNG

A sample docker config is provided in the docker directory.
Edit the file carbon-relay-ng.conf and substitute your ORG_ID and a valid API_KEY, then run:

```
docker-compose up
```

## Collecting metrics

The script can be run via cron, or manually:

```
usage: hg-synthetic.py [-h] [-i INSTANCE] [-o ORG_ID] [-u USERNAME]
                       [-p PASSWORD]

Check Hosted Grafana Login Process.

optional arguments:
  -h, --help            show this help message and exit
  -i INSTANCE, --instance INSTANCE
                        hosted grafana instance name
  -o ORG_ID, --orgid ORG_ID
                        hosted grafana orgid
  -u USERNAME, --user USERNAME
                        OAuth2 User
  -p PASSWORD, --password PASSWORD
                        OAuth2 Password
```

Example Usage:

```
hg-synthetics.py --instance bkgann3 --orgid 12774 --user bkgann --password <REDACTED>
```
