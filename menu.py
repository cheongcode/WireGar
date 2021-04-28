import click
import pyshark
from machinegar.TrainModels import *
from startup import *
import os
import subprocess
from click_shell import shell
from shlex import quote as shlex_quote
import pandas as pd


# Main Menu
@shell(prompt='wiregar >', intro='Select your module: [flowgar], [machinegar]. [netgar]')
def wiregar():
    """MODULE SELECTION"""
    pass


@wiregar.group()
def flowgar():
    """FOR FLOW CONVERSION"""
    pass


@wiregar.group()
def machinegar():
    """FOR MACHINE LEARNING"""
    pass


@wiregar.group()
def netgar():
    """FOR NETWORK TOOLS AND ANALYSIS"""
    pass


# Flowgar
@flowgar.command()
@click.argument('input')
@click.argument('csv')
def getflow(input, csv):
    """CLI to do Flow Conversion, [INPUT FILE] [OUTPUT FILE]"""
    os.system("python flowmaster.py -f {} -c {}".format(input, csv))


@flowgar.command()
@click.argument('pcapng')
@click.argument('pcap')
def pcapng2pcap(pcapng, pcap):
    """Converts a PCAPNG to PCAP, [PCAPNG] [PCAP]"""
    try:
        os.chdir(r"C:\Program Files\Wireshark")
        subprocess.run('tshark -F pcap -r {} -w {}'.format(pcapng, pcap), shell=True)
        click.echo("PCAPNG to PCAP Conversion Succeeded")
    except:
        click.echo("Error, unable to convert")


@machinegar.command()
def checkcsv():
    """Check if csv exists"""
    try:
        check = click.prompt('Input dataset to check: ')
        csv = pd.read_csv(check)
        click.echo(csv)
    except:
        click.echo("No CSV Detected")

@machinegar.command()
def train1():
    """Train the model with Random Forest Classifier"""
    try:
        trainRandomForestClassifier()
        click.echo("Random Forest Classifer Training Succeeded")
    except:
        click.echo("Error, unable to train")

@machinegar.command()
def train2():
    """Train the model with Decision Tree Classifier"""
    try:
        trainDecisionTreeClassifier()
        click.echo("Decision Tree Classifer Training Succeeded")
    except:
        click.echo("Error, unable to train")

# Netgar
@netgar.command()
def getlive():
    """Get 10 seconds of live data"""
    try:
        capture = pyshark.LiveCapture(output_file="live.pcap")
        capture.sniff(timeout=10)
        click.echo('10 Seconds of live network data captured')
    except:
        click.echo("Error, unable to get live data")


@netgar.command()
@click.argument('x')
def ping(x):
    """Ping a network"""
    click.echo(subprocess.run('ping ' + x), shell=True)


if __name__ == '__main__':
    logo()
    wiregar()
