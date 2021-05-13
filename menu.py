import pyshark
# from machinegar.TrainModels import *
from netgar.startup import *
import os
import subprocess
from click_shell import shell
import pandas as pd
import click
from rich import *
from Train import *
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Column, Table
from colorama import init

init()
console = Console()

with open("README2.md") as readme:
    markdown = Markdown(readme.read())
console.print(markdown)


# Main Menu
@shell(prompt='\033[0;31mwiregar>\033[00m', intro='Module Selection: [flowgar] [machinegar] [netgar]\n Type '
                                                  'in any module from the above '
                                                  'to start\n')
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

# @wiregar.command()
# def oneshot():
#     pass

# Flowgar
@flowgar.command()
@click.argument('inputpcap')
@click.argument('outputcsv')
def getflow(inputpcap, outputcsv):
    """Flow Converter, [INPUT PCAP FILE] [OUTPUT CSV FILE]"""
    try:
        os.system("python flowstart.py -f {} -c {}".format(os.path.abspath("datafolder/{}".format(inputpcap)),
                                                           os.path.abspath("datafolder/{}".format(outputcsv))))
        click.echo("Flow Conversion Succeeded")
    except:
        click.echo("Error, unable to convert")


@flowgar.command()
@click.argument('pcapng')
@click.argument('pcap')
def pcapng2pcap(pcapng, pcap):
    """Converts a PCAPNG to PCAP, [INPUT PCAPNG] [OUTPUT PCAP]"""
    try:
        os.chdir(r"C:\Program Files\Wireshark")
        subprocess.run('tshark -F pcap -r {} -w {}'.format(pcapng, pcap), shell=True)
        click.echo("PCAPNG to PCAP Conversion Succeeded")
    except:
        click.echo("Error, unable to convert")


@machinegar.command()
def checkcsv():
    """CSV Existence Check"""
    try:

        check = (click.prompt('Input dataset to check: '))
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


@machinegar.command()
def train3():
    """Train the model with Logistic Regression"""
    try:
        trainLogisticRegression()
        click.echo("Logistic Regression Training Succeeded")
    except:
        click.echo("Error, unable to train")


@machinegar.command()
def train4():
    """Train the model with SVM"""
    try:
        trainSVM()
        click.echo("SVM Training Succeeded")
    except:
        click.echo("Error, unable to train")


@machinegar.command()
def train5():
    """Train the model with GaussianNB"""
    try:
        trainGaussianNB()
        click.echo("GaussianNB Training Succeeded")
    except:
        click.echo("Error, unable to train")


@machinegar.command()
def train6():
    """Train the model with BernoulliNB"""
    try:
        trainBernoulliNB()
        click.echo("BernoulliNB Training Succeeded")
    except:
        click.echo("Error, unable to train")


@machinegar.command()
def trainall():
    """Train the model with all 6 models"""
    try:
        trainAll()
        click.echo("Succeeded in training all models")
    except:
        click.echo("Error, unable to train")


# Netgar
@netgar.command()
def getlive():
    """Get 10 seconds of live data"""
    try:
        capture = pyshark.LiveCapture(output_file="datafolder/live.pcap")
        capture.sniff(timeout=10)
        click.echo('10 Seconds of live network data captured')
    except:
        click.echo("Error, unable to get live data")


@netgar.command()
@click.argument('x')
def ping(x):
    """Ping a network"""
    click.echo(subprocess.run('ping ' + x))


if __name__ == '__main__':
    logo()
    wiregar()
