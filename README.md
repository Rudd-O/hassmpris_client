# Simple client to control the MPRIS multimedia agent

This package contains a simple command-line utility that allows you to pair
and then control any computer with the MPRIS Linux desktop agent.

It also contains an asyncio-based client class that permits your Python
programs to control media players on computers running the desktop agent.
This class is used in Home Assistant to provide access to media players via
the Home Assistant user interface.

## Setup

### Server

Install the [MPRIS Linux desktop agent](https://github.com/Rudd-O/hassmpris_agent)
on the computer you want to control remotely.

### This package

Install this package on the computer you want to control other machines from.
You'll find the program `hassmpris-client` installed here.

## Troubleshooting and help

Look at your system logs (e.g. if running this under Home Assistant, look at the
Home Assistant logs).  You should make a copy of any traceback of interest.

### Found a bug or a traceback?

Please report it in the [project's issue tracker](https://github.com/Rudd-O/hassmpris_client/issues).
