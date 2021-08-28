# Splunk PSTree Command

This apps main function is to enable a custom Splunk search command to reconstruct a pstree from Sysmon process creation events (EventCode 1). Information from memory forensics, such as Volatility's pstree, can be very helpful to detect malicious processes. By ingesting Sysmon events in Splunk and using this command you can quickly get similar information without performing memory forensics.  

## Prerequisites

* Ingest Process Creation Events with Parent Process information in Splunk

## Installation

There are several ways to implement the command. Here are two:
* Install from file - Click "Clone or Download" then "Downlad Zip". The tgz file in repo can be used with Splunk's "Install App from File"
* Copy splunk_pstree_app directory to etc - Clone the repo, then copy "splunk_pstree_app" directory to $SPLUNK_HOME/etc/apps

Installation by copying directory will require a restart of splunkd.

## Usage 

The pstree command requires two arguments, child and parent. The command is intended for sysmon EventCode=1 events but can be used for anything. The command returns a row for each root value with a multivalue field, "tree", containing the root value and all childern values.

Simple Sysmon Usage

```
index=sysmon EventCode=1 host=victim_machine
| pstree child=Image parent=ParentImage
| table tree
```

Detailed Sysmon Usage
```
index=sysmon EventCode=1 host=victim_machine
| rex field=ParentImage "\x5c(?<ParentName>[^\x5c]+)$"
| rex field=Image "\x5c(?<ProcessName>[^\x5c]+)$"
| eval parent = ParentName." (".ParentProcessId.")"
| eval child = ProcessName." (".ProcessId.")"
| eval detail=strftime(_time,"%Y-%m-%d %H:%M:%S")." ".CommandLine
| pstree child=child parent=parent detail=detail spaces=50
| table tree
```

To report problems, please go to issues section on Github

https://github.com/murchisd/splunk_pstree_app/issues

Built By Donald Murchison

