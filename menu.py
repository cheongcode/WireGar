import csv
import glob
import shutil

from netgar.startup import *
import subprocess
from click_shell import shell
from Train import *
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Column, Table
from colorama import init
from path import Path
from rich import box
import datetime
import pyshark
import pandas as pd

init()
console = Console()


# Main Menu

@shell(prompt='\033[0;31mwiregar>\033[00m', intro='Module Selection: [flowgar] [machinegar] [netgar] [swiftgar] ['
                                                  'classgar] \n Type '
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


@wiregar.group()
def classgar():
    """FOR EVALUATION OF SAVED MODELS ON UNKNOWN DATA"""
    pass


@wiregar.group()
def swiftgar():
    """FOR SINGLE COMMAND CONVERSION AND MACHINE LEARNING"""
    pass


# Flowgar
@flowgar.command()
@click.argument('inputpcap')
@click.argument('outputcsv')
def getflow(inputpcap, outputcsv):  # Convert to Flow
    """Flow Converter, [INPUT PCAP FILE] [OUTPUT CSV FILE]"""
    try:
        os.system("python flowstart.py -f {} -c {}".format(os.path.abspath("datafolder/{}".format(inputpcap)),
                                                           os.path.abspath("datafolder/{}".format(outputcsv))))
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#00ff00]Flow Conversion Succeeded[/#00ff00]")
        console.print(table)
    except:
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#ff0000]Error, unable to convert[/#ff0000]")
        console.print(table)


@flowgar.command()
@click.argument('pcapng')
@click.argument('pcap')
def pcapng2pcap(pcapng, pcap):  # Convert PCAPNG to PCAP
    """Converts a PCAPNG to PCAP, [INPUT PCAPNG] [OUTPUT PCAP]"""
    try:
        pcapngpath = Path('datafolder/{}'.format(pcapng)).abspath()
        pcappath = Path('datafolder/{}'.format(pcap)).abspath()
        os.chdir(r"C:\Program Files\Wireshark")
        subprocess.Popen('tshark -F pcap -r {} -w {}'.format(pcapngpath, pcappath), shell=True, stdout=subprocess.PIPE)
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#00ff00]PCAPNG to PCAP Conversion Succeeded[/#00ff00]")
        console.print(table)
    except:
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#ff0000]Error, unable to convert[/#ff0000]")
        console.print(table)

    # Old Converter
    # try:
    #     os.chdir(r"C:\Program Files\Wireshark")
    #     subprocess.run('tshark -F pcap -r {} -w {}'.format(pcapng, pcap), shell=True)
    #     click.echo(click.style("PCAPNG to PCAP Conversion Succeeded", fg='green'))
    # except:
    #     click.echo("Error, unable to convert")


@machinegar.command()
def trainRFC():
    """Train the model with Random Forest Classifier"""

    try:
        trainRandomForestClassifier()
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#00ff00]Random Forest Classifier Training Succeeded[/#00ff00]")
        console.print(table)
    except:
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#ff0000]Error, Unable To Train[/#ff0000]")
        console.print(table)


@machinegar.command()
def trainDTC():
    """Train the model with Decision Tree Classifier"""
    try:
        trainDecisionTreeClassifier()
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#00ff00]Decision Tree Classifier Training Succeeded[/#00ff00]")
        console.print(table)
    except:
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#ff0000]Error, Unable To Train[/#ff0000]")
        console.print(table)


@machinegar.command()
def trainLR():
    """Train the model with Logistic Regression"""
    try:
        trainLogisticRegression()
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#00ff00]Logistic Regression Training Succeeded[/#00ff00]")
        console.print(table)
    except:
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#ff0000]Error, Unable To Train[/#ff0000]")
        console.print(table)


# @machinegar.command()
# def trainSVM():
#     """Train the model with SVM"""
#     try:
#         trainSVM()
#         table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
#         table.add_row("[#00ff00]Support Vector Machine Training Succeeded[/#00ff00]")
#         console.print(table)
#     except:
#         table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
#         table.add_row("[#ff0000]Error, Unable To Train[/#ff0000]")
#         console.print(table)


@machinegar.command()
def trainGNB():
    """Train the model with GaussianNB"""
    try:
        trainGaussianNB()
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#00ff00]GaussianNB Training Succeeded[/#00ff00]")
        console.print(table)
    except:
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#ff0000]Error, Unable To Train[/#ff0000]")
        console.print(table)


@machinegar.command()
def trainBNB():
    """Train the model with BernoulliNB"""
    try:
        trainBernoulliNB()
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#00ff00]BernoulliNB Training Succeeded[/#00ff00]")
        console.print(table)
    except:
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#ff0000]Error, Unable To Train[/#ff0000]")
        console.print(table)


@machinegar.command()
def trainAll():
    """Train the model with all 6 models"""
    try:
        trainAllModels()
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#00ff00]Succeeded In Training All Models[/#00ff00]")
        console.print(table)
    except:
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#ff0000]Error, Unable To Train[/#ff0000]")
        console.print(table)


# Netgar
@netgar.command()
@click.argument('seconds', type=int)
def getliveseconds(seconds):
    """Get live data in any amount of seconds"""
    try:
        capture = pyshark.LiveCapture(output_file="datafolder/live.pcap")
        capture.sniff(timeout=seconds)
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#00ff00]{} Seconds Of Live Network Data Captured[/#00ff00]".format(seconds))
        console.print(table)
        capture.close()
    except:
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#ff0000]Error, Unable To Get Live Data[/#ff0000]")
        console.print(table)


@netgar.command()
def getconstantlive():
    """Get Constant Data at every 5 minute intervals"""
    count = 0
    try:
        while True:
            count += 1
            date = datetime.datetime.now()
            file = 'captures/' + str(count) + "-" + str(date.day) + "-" + str(date.month) + "-" + str(
                date.year) + '.pcap'
            capture = pyshark.LiveCapture(output_file=file)
            capture.sniff(timeout=3)
            table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
            table.add_row("[#00ff00]Live Network Data Captured From {} to {}[/#00ff00]".format(
                datetime.datetime.now() - datetime.timedelta(minutes=5), datetime.datetime.now()))
            console.print(table)
            capture.close()
            capture.clear()

    except KeyboardInterrupt:
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#ff0000]Constant Live Terminated[/#ff0000]")
        console.print(table)
        pass


@netgar.command()
@click.argument('x')
def ping(x):
    """Ping a network"""
    click.echo(subprocess.run('ping ' + x))


@classgar.command()
def start():
    """Classification with saved model """
    table = Table(show_header=False, title="\n[#8A2BE2]List of Datasets:[/#8A2BE2]", box=box.HORIZONTALS)
    basepath = 'datafolder/'
    for entry in os.listdir(basepath):
        name, ext = os.path.splitext(entry)
        if os.path.isfile(os.path.join(basepath, entry)):
            if ext == '.csv':
                table.add_row(entry)
    console.print(table)
    check = input("\nInput Unknown Data: ")
    os.listdir(basepath)
    idsdata = pd.read_csv(basepath + check)
    df = pd.DataFrame(idsdata)
    # Data Clean
    df = df.replace([np.inf, -np.inf], np.nan).dropna(axis=0)
    df.drop(df.columns[[0, 1, 2, 3]], axis=1, inplace=True)
    df.drop(df.columns[[2]], axis=1, inplace=True)
    print(df)
    X = df.iloc[:, :-1].values
    y = df.iloc[:, -1].values

    # Select Test Size
    # testsize = float(click.prompt('\nInput test size: [float value]'))
    # X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize, random_state=0)

    table = Table(show_header=False, title="\n[#8A2BE2]List of Saved Models:[/#8A2BE2]", box=box.HORIZONTALS)
    basepath2 = 'savedmodels/'
    for entry in os.listdir(basepath2):
        name, ext = os.path.splitext(entry)
        if os.path.isfile(os.path.join(basepath2, entry)):
            table.add_row(entry)
    console.print(table)
    check2 = input("\nInput Saved Model: ")
    os.listdir(basepath2)
    storedmodel = basepath2 + check2
    loaded_model = pickle.load(open(storedmodel, 'rb'))
    prediction = loaded_model.predict(X)
    # Save Prediction
    savepath = 'classgar/'
    rmext = os.path.splitext(check)[0]
    addname = os.path.join('(predicted)')
    savefile = savepath + rmext + addname + "data"
    orig = basepath + check
    target = savefile + ".csv"
    shutil.copyfile(orig, target)
    # pd.DataFrame(prediction, columns=['predictions']).to_csv(savepath + "datatemp.csv")
    data = pd.read_csv(target)
    # data.insert(-1, "Prediction", prediction)
    data['Prediction'] = prediction
    data.to_csv(target, index=False)
    table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
    table.add_row("[#4682B4]Prediction Saved[/#4682B4]")
    console.print(table)


@swiftgar.command()
@click.argument('pcapng')
def start(pcapng):
    """Input a PCAPNG file to get trained models"""
    # File Check
    owd = os.getcwd()
    print(owd)
    if os.path.exists("datafolder/{}".format(pcapng)):
        click.echo("File Exist, Converting to PCAP")

    else:
        click.echo("File does not exist")
        start()
    # Extension Change (PCAP)
    pcap = pcapng.replace('pcapng', 'pcap')
    # PCAPNG to PCAP Conversion
    try:
        pcapngpath = Path('datafolder/{}'.format(pcapng)).abspath()
        pcappath = Path('datafolder/{}'.format(pcap)).abspath()
        os.chdir(r"C:\Program Files\Wireshark")
        subprocess.Popen('tshark -F pcap -r {} -w {}'.format(pcapngpath, pcappath), shell=True, stdout=subprocess.PIPE)
        click.echo("PCAPNG to PCAP Conversion Succeeded")
    except:
        click.echo("Error, unable to convert")
    # Extension Change (CSV)
    outputcsv = pcap.replace('pcap', 'csv')
    click.echo(owd)
    os.chdir(owd)
    try:
        os.system("python flowstart.py -f {} -c {}".format(os.path.abspath("datafolder/{}".format(pcap)),
                                                           os.path.abspath("datafolder/{}".format(outputcsv))))
        click.echo("Flow Conversion Succeeded")
    except:
        click.echo("Error, unable to convert")
    basepath = 'datafolder/'
    idsdata = pd.read_csv(basepath + outputcsv)
    df = pd.DataFrame(idsdata)
    # Data Clean
    df = df.replace([np.inf, -np.inf], np.nan).dropna(axis=0)
    df.drop('timestamp', inplace=True, axis=1)
    df.drop('src_ip', inplace=True, axis=1)
    df.drop('dst_ip', inplace=True, axis=1)
    X = df.iloc[:, :-1].values
    y = df.iloc[:, -1].values

    # Input Test Size
    testsize = float(click.prompt('Input test size: [float value]'))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize, random_state=0)

    # Random Forest Classifier
    from sklearn.ensemble import RandomForestClassifier
    clf = RandomForestClassifier(n_estimators=300)
    np.nan_to_num(X_train)
    np.nan_to_num(y_train)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    from sklearn import metrics

    print("Random Forest Classifier Result: ")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Precision")
    table.add_column("Recall")
    table.add_column("Accuracy", justify="right")
    table.add_column("F1 Score", justify="right")
    p = str(metrics.precision_score(y_test, y_pred, average='macro'))
    r = str(metrics.recall_score(y_test, y_pred, average='macro'))
    a = str(metrics.accuracy_score(y_test, y_pred))
    f = str(metrics.f1_score(y_test, y_pred, average='macro'))
    table.add_row(
        p,
        r,
        a,
        f
    )
    # round p
    rp = Decimal(p)
    round(rp, 2)
    nep = str(round(rp, 2))
    # round r
    rr = Decimal(r)
    round(rr, 2)
    ner = str(round(rr, 2))
    # round a
    ra = Decimal(a)
    nea = str(round(ra, 2))
    # round f
    rf = Decimal(f)
    nef = str(round(rf, 2))
    table.add_row(
        nep,
        ner,
        nea,
        nef
    )
    console.print(table)
    RAcc = metrics.accuracy_score(y_test, y_pred)
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))

    # Decision Tree Classifier
    from sklearn.tree import DecisionTreeClassifier
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize, random_state=1)
    dt = DecisionTreeClassifier()
    np.nan_to_num(X_train)
    np.nan_to_num(y_train)
    dt.fit(X_train, y_train)
    y_pred = dt.predict(X_test)
    from sklearn import metrics

    print("Decision Tree Classifier Result: ")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Precision")
    table.add_column("Recall")
    table.add_column("Accuracy", justify="right")
    table.add_column("F1 Score", justify="right")
    p = str(metrics.precision_score(y_test, y_pred, average='macro'))
    r = str(metrics.recall_score(y_test, y_pred, average='macro'))
    a = str(metrics.accuracy_score(y_test, y_pred))
    f = str(metrics.f1_score(y_test, y_pred, average='macro'))
    table.add_row(
        p,
        r,
        a,
        f
    )
    # round p
    rp = Decimal(p)
    round(rp, 2)
    nep = str(round(rp, 2))
    # round r
    rr = Decimal(r)
    round(rr, 2)
    ner = str(round(rr, 2))
    # round a
    ra = Decimal(a)
    nea = str(round(ra, 2))
    # round f
    rf = Decimal(f)
    nef = str(round(rf, 2))
    table.add_row(
        nep,
        ner,
        nea,
        nef
    )
    console.print(table)
    DAcc = metrics.accuracy_score(y_test, y_pred)
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))

    # Logistic Regression
    from sklearn.linear_model import LogisticRegression
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize, random_state=0)
    logreg = LogisticRegression(solver='sag')
    logreg.fit(X_train, y_train)
    y_pred = logreg.predict(X_test)

    from sklearn import metrics
    print("Logistic Regression Result: ")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Precision")
    table.add_column("Recall")
    table.add_column("Accuracy", justify="right")
    table.add_column("F1 Score", justify="right")
    p = str(metrics.precision_score(y_test, y_pred, average='macro'))
    r = str(metrics.recall_score(y_test, y_pred, average='macro'))
    a = str(metrics.accuracy_score(y_test, y_pred))
    f = str(metrics.f1_score(y_test, y_pred, average='macro'))
    table.add_row(
        p,
        r,
        a,
        f
    )
    # round p
    rp = Decimal(p)
    round(rp, 2)
    nep = str(round(rp, 2))
    # round r
    rr = Decimal(r)
    round(rr, 2)
    ner = str(round(rr, 2))
    # round a
    ra = Decimal(a)
    nea = str(round(ra, 2))
    # round f
    rf = Decimal(f)
    nef = str(round(rf, 2))
    table.add_row(
        nep,
        ner,
        nea,
        nef
    )
    console.print(table)
    LAcc = metrics.accuracy_score(y_test, y_pred)
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))

    # SVM

    # GuassianNB
    from sklearn.naive_bayes import GaussianNB
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize)
    gnb = GaussianNB()
    gnb.fit(X_train, y_train)
    y_pred = gnb.predict(X_test)
    from sklearn import metrics

    print("GaussianNB Result: ")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Precision")
    table.add_column("Recall")
    table.add_column("Accuracy", justify="right")
    table.add_column("F1 Score", justify="right")
    p = str(metrics.precision_score(y_test, y_pred, average='macro'))
    r = str(metrics.recall_score(y_test, y_pred, average='macro'))
    a = str(metrics.accuracy_score(y_test, y_pred))
    f = str(metrics.f1_score(y_test, y_pred, average='macro'))
    table.add_row(
        p,
        r,
        a,
        f
    )
    # round p
    rp = Decimal(p)
    round(rp, 2)
    nep = str(round(rp, 2))
    # round r
    rr = Decimal(r)
    round(rr, 2)
    ner = str(round(rr, 2))
    # round a
    ra = Decimal(a)
    nea = str(round(ra, 2))
    # round f
    rf = Decimal(f)
    nef = str(round(rf, 2))
    table.add_row(
        nep,
        ner,
        nea,
        nef
    )
    console.print(table)
    GAcc = metrics.accuracy_score(y_test, y_pred)
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))

    # BernoulliNB
    from sklearn.naive_bayes import BernoulliNB
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize)
    gnb = BernoulliNB()
    gnb.fit(X_train, y_train)
    y_pred = gnb.predict(X_test)
    from sklearn import metrics

    print("BernoulliNB Result: ")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Precision")
    table.add_column("Recall")
    table.add_column("Accuracy", justify="right")
    table.add_column("F1 Score", justify="right")
    p = str(metrics.precision_score(y_test, y_pred, average='macro'))
    r = str(metrics.recall_score(y_test, y_pred, average='macro'))
    a = str(metrics.accuracy_score(y_test, y_pred))
    f = str(metrics.f1_score(y_test, y_pred, average='macro'))
    table.add_row(
        p,
        r,
        a,
        f
    )
    # round p
    rp = Decimal(p)
    round(rp, 2)
    nep = str(round(rp, 2))
    # round r
    rr = Decimal(r)
    round(rr, 2)
    ner = str(round(rr, 2))
    # round a
    ra = Decimal(a)
    nea = str(round(ra, 2))
    # round f
    rf = Decimal(f)
    nef = str(round(rf, 2))
    table.add_row(
        nep,
        ner,
        nea,
        nef
    )
    console.print(table)
    BAcc = metrics.accuracy_score(y_test, y_pred)
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))

    ranking = [RAcc, DAcc, LAcc, GAcc, BAcc]
    ranking.sort()
    print("Summary: ")
    print("Highest Accuracy: ", ranking[-1])
    if ranking[-1] == RAcc:
        console.print("Suggested Model: Random Forest Classifier", style="#00FF00")
    elif ranking[-1] == DAcc:
        console.print("Suggested Model: Decision Tree Classifier", style="#00FF00")
    elif ranking[-1] == LAcc:
        console.print("Suggested Model: Logistic Regression", style="#00FF00")
    elif ranking[-1] == GAcc:
        console.print("Suggested Model: GaussianNB", style="#00FF00")
    elif ranking[-1] == BAcc:
        console.print("Suggested Model: BernoulliNB", style="#00FF00")


if __name__ == '__main__':
    progress()
    with open("README2.md") as readme:
        markdown = Markdown(readme.read())
    console.print(markdown)
    logo()
    wiregar()
