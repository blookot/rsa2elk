# RSA2ELK

Converts Netwitness log parser configuration to Logstash configuration

**Disclamer: RSA2ELK is being published as an independent project (by Vincent Maury) and is in no way associated with, endorsed, or supported by Elastic. RSA2ELK is hereby released to the public as unsupported, open source software. Vincent Maury or Elastic cannot be held responsible for the use of this script! Use it at your own risk**


## Introduction (the why)

The purpose of this tool is to convert an existing configuration made for RSA Netwitness Log Parser software (ingestion piece of the RSA SIEM) into a Logstash configuration that can ingest logs to Elasticsearch.

RSA uses one configuration file per device source (product). For example, one file will handle F5 ASM, another one will handle F5 APM, etc.

Please note that RSA released the configuration files for 300 devices [on github](https://github.com/netwitness/nw-logparsers) with the Apache 2.0 license. So if you are not an RSA user, you can still pass any of these configuration files to the rsa2elk tool to generate the corresponding Logstash pipeline.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine.

### Prerequisites

This piece of python has no other pre-requisite than **Python 3**.
No need for additional library.
It should work on any platform (tested on Windows so far).

### Running the script

Just clone this repository and run the script on the sample zScaler file.

```
git clone https://github.com/blookot/rsa2elk.git
cd rsa2elk
python rsa2elk.py -h
python rsa2elk.py -p -q -e -f -r -t
# replace the log line in the input by the following string: `data as a start ZSCALERNSS: time=hfld2 Jan 30 15:12:07 2020^^timezone=UTC^^action=action^^reason=result^^hostname=vincent.hostname^^protocol=tcp^^serverip=34.103.179.90^^url=https://www.elastic.co/blog/first-posts.php^^urlcategory=Awesome websites^^urlclass=Info on elastic.co^^dlpdictionaries=fld3^^dlpengine=fld4^^filetype=php^^threatcategory=None^^threatclass=No threat^^pagerisk=fld8^^threatname=N/A^^clientpublicIP=fld9^^ClientIP=2a01:cb04:a99:1700:cc1:94df:81c4:9dcd^^location=france^^refererURL=web_referer^^useragent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36^^department=user_dept^^user=username^^event_id=id^^clienttranstime=fld17^^requestmethod=GET^^requestsize=178^^requestversion=HTTP/1.0^^status=200^^responsesize=1589^^responseversion=fld23^^transactionsize=1812`
logstash -f logstash-zscalernssmsg.conf
```

The script has several options:
* `-h` will display help.
* `-i` or `--input-file FILE` to enter the absolute patch to the RSA XML configuration file. Alternative is url. See the note below for custom XML file.
* `-u` or `--url URL` to enter the URL to the RSA XML configuration file. if no file or url is provided, this program will run on a [sample XML file](https://raw.githubusercontent.com/netwitness/nw-logparsers/master/devices/zscalernss/zscalernssmsg.xml) located in the RSA repo.
* `-o` or `--output-file FILE` to enter the absolute path to the Logstash .conf file (default: `logstash-[device].conf`).
* `-p` or `--parse-url` adds a pre-defined filter block (see [filter-url.conf](filter-url.conf)) to parse URLs into domain, query, etc (default: false).
* `-q` or `--parse-ua` adds a pre-defined filter block (see [filter-ua.conf](filter-ua.conf)) to parse User Agents (default: false).
* `-e` or `--enrich-geo` adds a filter block (see [filter-geoip.conf](filter-geoip.conf)) to enrich public IPs with geoip information (default: false).
* `-f` or `--enrich-asn` adds a filter block (see [filter-asn.conf](filter-asn.conf)) to enrich public IPs with ASN information (default: false).
* `-x` or `--remove-parsed-fields` removes the event.original and message fields if correctly parsed (default: false).
* `-r` or `--rename-ecs` renames default RSA fields to ECS fields (default: false).
* `-t` or `--trim-fields` trims (strips left and right spaces) from all string fields (default: false).
* `-n` or `--no-grok-anchors` removes the begining (^) and end ($) anchors in grok (default: false, ie default is to have them).
* `-a` or `--add-stop-anchors` adds hard stop anchors in grok to ignore in-between chars, see explanation below. Should be set as a serie of plain characters, only escaping " and \\. Example: `\"()[]` (default: "").
* `-m` or `--single-space-match` to only match 1 space in the log if there is 1 space in the RSA parser (default: false, ie match 1-N spaces aka `[\s]+`).
* `-c` or `--check-config` runs on check of the generated configuration with `logstash -t` (default: false).
* `-l` or `--logstash-path` to enter the absolute path to logstash bin executable (default is my local path!).
* `-d` or `--debug` to enable debug mode, more verbose (default: false).

### Input

The XML configuration file can be specified using the `-i` option for a local file or `-u` option for a URL.
When specifying a local file, for instance `networkdevice.xml`, the script will also look for a related "custom" XML file named `networkdevice-custom.xml`. If it exists, the script will take each entry (header & message) of the custom XML and insert them in the "main" XML tree. See [RSA doc](https://community.rsa.com/docs/DOC-83425) for more documentation.

### Customize pipeline input & output

The tool mostly generates the `filter` part of the Logstash configuration. The `input` and `output` sections are copied from the [input.conf](input.conf) and [output.conf](output.conf) files that you can customize.

Note: the [filter-url.conf](filter-url.conf) file adds a section at the end of the Logstash configuration to deal with urls. The [filter-ua.conf](filter-ua.conf) parses user agents. Both files can be customized, partially commented... In particular, the user-agent parsing can be resource intensive.

Note: the [filter-geoip.conf](filter-geoip.conf) and [filter-asn.conf](filter-asn.conf) enrichments are also lookups on large tables which can be resource intensive. 

### Output

The script generates 3 outputs:
* `logstash-[device].conf` which is the main Logstash pipeline configuration
* `es-mapping.json` is the Elasticsearch mapping file
* `output-logstash-[device]-configtest.txt` in case the `-c` option has been activated to test the configuration

You can grab the `logstash-[device].conf` file (or custom name you defined) generated by this script.
If you use the Elasticsearch output of the generated pipeline, you will see the use of a template linking to the `es-mapping.json` file. You should add the absolute path to this file in the `template` key (of the pipeline config) when you run Logstash.

When the `check-config` flag has been activated, this configuration file is automatically tested by Logstash. The output of Logstash can be checked in the `output-logstash-[device]-configtest.txt` file that is created in the same directory than the rsa xml file input.

## Understanding the tool (the how)

RSA Netwitness Log Parser is the piece of software ingesting data in the Netwitness platform. It comes with a nice UI (see [the user guide](https://community.rsa.com/docs/DOC-85016)).
Elastic also provides 2 ways to ingest data into Elasticsearch: Logstash - as an ETL - and the Elasticsearch ingest pipelines. This tool focuses on Logstash, as a way to ease ingest (capturing data via syslog, files, etc and writing to elasticsearch or other destinations) but the plan is to port this tool to the Elasticsearch ingest pipeline (leveraging Filebeat as syslog termination).

### The syntax

The syntax of the XML configuration file is specific to RSA and falls into 2 parts mainly:
* headers, describing headers of logs, capturing the first fields that are common to many types of messages. These headers then point (using the `messageid` field) to the appropriate message parser
* messages, parsing the whole log line, extracting fields, computing the event time (`EVNTTIME` function), concatenating strings and fields to generate new ones (`STRCAT` function), setting additional fields with static or dynamic values, etc

In both, the `content` attribute describes how the log is parsed. The syntax supports alternatives `{a|b}`, field extraction `<fld1>` and static strings.

The `transform.py` module does the core of the conversion by reading this content line character after character and computing the corresponding grok or dissect pattern.
Dissect is prefered by default, as it performs faster and easily matches the RSA syntax. However, Dissect does not support alternatives `{a|b}` and (specifically for headers) it does not support sub group capturing with the `payload` field. So, for both cases, we fallback to grok.

#### Dissect

When dissect is possible, transformation is easy: "just" replace <fld> with %{fld}! As simple as that.
And performance should improve (see a [feature & perf comparison](https://www.elastic.co/blog/logstash-dude-wheres-my-chainsaw-i-need-to-dissect-my-logs)).

#### Grok

The whole idea of the grok pattern is to capture fields with any character but the one after the field. For example, `<fld1> <fld2>` in RSA will result in `?<fld1>[^\s]*)[\s]+(?<fld2>.*)` in grok. Note that the `[\s]+` in the middle is quite permissive because many products use several spaces to tabularize their logs. The `-s` flag can be used to change this behavior to strictly match the log according to the exact number of spaces in the RSA configuration. This flag will replace the `[\s]+` by a simple `\s`.

RSA can also handle missing fields when reading specific characters. For example, this RSA parser `<fld1> "<fld99>"` will match both `aaa "zzz"` (where fld1='aaa') and `aaa bbb "zzz"` (where fld1='aaa bbb').
The `-a` flag will let the user input specific characters that will serve as anchors, so that when they are found, the grok will jump over the unexpected fields. Using the above example, the grok will look like `(?<fld1>[^\s]*)[\s]+(?<anchorfld>[^\"]*)\"(?<fld99>[^\"]+)\"`. Please note that we are adding a `anchorfld` field to capture the possible characters before the anchor, so for `aaa bbb "zzz"`, the `anchorfld` field will only have 'bbb'). Which is what you would expect I think ;-)

### RSA meta fields to Elastic Common Schema (ECS)

RSA uses specific field names in the configuration files that map to meta keys, as described [here](https://community.rsa.com/community/products/netwitness/blog/2017/11/13/rsa-meta-dictionary-tool).
Elastic also defined a set of meta fields called ECS, see [documentation](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html).

The [table-map.csv](table-map.csv) file is used to map RSA meta fields to ECS naming (as well as field types).
You can customize this file and change key mappings as you like, as long as you keep this csv format (with , or ; separator) and the correct column titles.
The support of `table-map.xml` and `table-map-custom.xml` is planned (see TODO below).

## Changelog (since v1)

The main changes since [v1](v1/) are listed here:
* dissect is now used (instead of grok) when the RSA header parser doesn't have a specific field as payload, and when the message parser has no alternatives. Should result in performance increase.
* the script now also reads the `-custom` device XML file 
* generate the Elasticsearch index mapping (template)
* support ip geoloc & asn enrichment as new options
* mutate strip (whitespace removal) all text fields as a new option
* read XML headers to grab the configuration device name & group
* support PARMVAL & HDR functions to set message id value
* support functions in header parsing (content) string as well
* better handling of encoding (XML being in ISO-8859-1 and logstash output file in UTF-8)
* renaming rsa fields to ECS is now an option (is ECS is not mandatory, don't rename)
* add grok/dissect id to help monitoring, see [pipeline viewer doc](https://www.elastic.co/guide/en/logstash/current/logstash-pipeline-viewer.html) and [logstash diag](https://github.com/elastic/support-diagnostics#logstash-diagnostics)

## TODO

There are still a few ideas to improve this rsa2elk:
* support value map (key/value translation)
* optimize the few (very) long RSA configuration files that have the same message parser multiple times
* input a custom `table-map.xml` and `table-map-custom.xml` (RSA customers) for custom fields
* support additional custom enrichment with external files (RSA customers)
* port this converter to Elasticsearch ingest pipeline (see [documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/pipeline.html)), specially since Elasticsearch 7.5 added an enrichment processor

## Authors

* **Vincent Maury** - *Initial commit* - [blookot](https://github.com/blookot)

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* First things first, I should thank RSA for sharing such content and helping the community with great resources!
* Many thanks to my Elastic colleagues for their support, in particular @andsel, @jsvd and @yaauie from the Logstash team, as well as @webmat and @melvynator for the ECS mapping
* Thanks also to my dear who let me work at nights and week-ends on this project :-*
