# Splunk PSTree Command

This apps main function is to enable a custom Splunk search command to reconstruct a pstree from Sysmon process creation events (EventCode 1). Information from memory forensics, such as Volatility's pstree, can be very helpful to detect malicious processes. By ingesting Sysmon events in Splunk and using this command you can quickly get similar information without performing memory forensics.  

![Splunk PSTree](https://github.com/murchisd/murchisd.github.io/raw/master/assets/splunk/pstree.JPG)

## Prerequisites

* Splunk Python SDK - [Install Splunk SDK for Python](http://dev.splunk.com/view/python-sdk/SP-CAAAEDG)
* Ingest Sysmon Process Creation Events in Splunk

## Installation

There are several ways to implement the command. Here are two:
* Install from file - Click "Clone or Download" then "Downlad Zip". The zip file can be used with Splunk's "Install App from File"
* Copy app to etc - Clone the repo, then copy "splunk_pstree_app" directory to $SPLUNK_HOME/etc/apps

Installation will require a restart of splunkd.

## Usage 

The pstree command requires two arguments, child and parent. The command is intended for sysmon EventCode=1 events but can be used for anything. The command returns a row for each root value with a multivalue field, "tree", containing the root value and all childern values.

Simple Sysmon Usage

```
index=sysmon EventCode=1 host=victim_machine
| pstree child=Image parent=ParentImage
| table tree
```

Pretty Sysmon Usage
```
index=sysmon EventCode=1 host=victim_machine
| rex field=ParentImage "\x5c(?<ParentName>[^\x5c]+)$"
| rex field=ParentImage "\x5c(?<ProcessName>[^\x5c]+)$"
| eval parent = ParentName." (".ParentProcessId.")"
| eval child = ProcessName." (".ProcessId.")"
| table parent child
| pstree child=child parent=parent
| table tree
```

Other Example (Family Tree) - fullName, childOf, birthdate
```
index=family
| pstree parent=childOf child=fullName
| table tree
```

