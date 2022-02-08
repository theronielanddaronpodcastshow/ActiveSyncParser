# ActiveSyncParser
The RDPS ActiveSync Parser (ASP) is a Java application designed to aggregate and parse Active Sync logs from Microsoft Exchange, grouping the log entries by device ID and then organising them by event date-time and outputting the results.  This tool allows _filtering_ of event logs by device ID, as well, allowing rapid parsing of one or more ActiveSync log files for use in identifying inappropriate or malicious activity, tying activity to specific devices, and quickly filtering through logs.

## Requirements ##
Apache Maven 3.6 or above
npm 7.11 or above
Java 11 or above

## Installation ##
The RDPS ASP is composed of a Java stand-alone application. It is built by simply running:
mvn clean package

This creates an executable JAR in target -- asp.jar.

## Execution ##
To execute the application, simply run `java -jar asp.jar [--keep <device_id>] [...ActiveSyncLogFiles] [...ActiveSyncLogFileRegex]`

For example:

`java -jar asp.jar ~/logs/*.txt --keep B3RSN5UKG50EN57F4L9LMRBMRS > requests.txt` 

This will parse all .txt files in ~/logs, extracting out only the activity tied to the device `B3RSN5UKG50EN57F4L9LMRBMRS` and output it to requests.txt.

## Future Plans ##
1. Switch to use JCommander.  It's fantastic.
2. Add in reporting options that allow outputting in different formats and directly to file, instead of just dumping to stdout.
