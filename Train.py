import click
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import os
from rich import *
from rich.console import Console
from rich.table import Column, Table
from decimal import Decimal
import pickle
from sklearn import metrics
from rich import box

console = Console()

import warnings

warnings.filterwarnings('ignore')  # "error", "ignore", "always", "default", "module" or "once"


def trainRandomForestClassifier():
    # Select Dataset from Folder
    table = Table(show_header=False, title="\n[#8A2BE2]List of Datasets:[/#8A2BE2]", box=box.HORIZONTALS)
    basepath = 'datafolder/'
    for entry in os.listdir(basepath):
        name, ext = os.path.splitext(entry)
        if os.path.isfile(os.path.join(basepath, entry)):
            if ext == '.csv':
                table.add_row(entry)
    console.print(table)
    check = input("\nInput Data: ")
    os.listdir(basepath)
    idsdata = pd.read_csv(basepath + check)
    df = pd.DataFrame(idsdata)

    # Data Clean
    df = df.replace([np.inf, -np.inf], np.nan).dropna(axis=0)
    df['Timestamp'] = df['Timestamp'].str.replace(" ", "") \
        .str.replace("/", "").str.replace(":", "")
    X = df.iloc[:, :-1].values
    y = df.iloc[:, -1].values

    # Select Test Size
    testsize = float(click.prompt('\nInput test size: [float value]'))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize, random_state=0)

    # Machine Learning
    from sklearn.ensemble import RandomForestClassifier
    clf = RandomForestClassifier(n_estimators=300)
    np.nan_to_num(X_train)
    np.nan_to_num(y_train)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    # Print Output
    from sklearn import metrics
    table = Table(title="\nRandom Forest Classifier Results", show_header=True, header_style="bold magenta")
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
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))

    # Save Function
    savepath = 'savedmodels/'
    save = (click.prompt(click.style('\nWould you like to save the trained model ?(Y/N)', fg='yellow')))
    if save == 'Y' or save == 'y':
        clf.fit(X_train, y_train)
        rmext = os.path.splitext(check)[0]
        addname = os.path.join('(rfc)')
        savefile = savepath + rmext + addname
        pickle.dump(clf, open(savefile, 'wb'))
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#4682B4]Model Saved[/#4682B4]")
        console.print(table)
    else:
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#FF8C00]Model Not Saved[/#FF8C00]")
        console.print(table)
        pass


def trainDecisionTreeClassifier():
    # Select Dataset from Folder
    table = Table(show_header=False, title="\n[#8A2BE2]List of Datasets:[/#8A2BE2]", box=box.HORIZONTALS)
    basepath = 'datafolder/'
    for entry in os.listdir(basepath):
        name, ext = os.path.splitext(entry)
        if os.path.isfile(os.path.join(basepath, entry)):
            if ext == '.csv':
                table.add_row(entry)
    console.print(table)
    check = input("\nInput Data: ")

    os.listdir(basepath)
    idsdata = pd.read_csv(basepath + check)
    df = pd.DataFrame(idsdata)

    # Data Clean
    df = df.replace([np.inf, -np.inf], np.nan).dropna(axis=0)
    df['Timestamp'] = df['Timestamp'].str.replace(" ", "") \
        .str.replace("/", "").str.replace(":", "")
    X = df.iloc[:, :-1].values
    y = df.iloc[:, -1].values
    # Select Test Size
    testsize = float(click.prompt('\nInput test size: [float value]'))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize, random_state=1)

    # Machine Learning
    from sklearn.tree import DecisionTreeClassifier
    dt = DecisionTreeClassifier()
    np.nan_to_num(X_train)
    np.nan_to_num(y_train)
    dt.fit(X_train, y_train)
    y_pred = dt.predict(X_test)

    # Print Output
    table = Table(title="\nDecision Tree Classifier Result: ", show_header=True, header_style="bold magenta")
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
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))

    # Save Function
    savepath = 'savedmodels/'
    save = (click.prompt(click.style('Would you like to save the trained model ?(Y/N)', fg='yellow')))
    if save == 'Y' or save == 'y':
        dt.fit(X_train, y_train)
        rmext = os.path.splitext(check)[0]
        addname = os.path.join('(rfc)')
        savefile = savepath + rmext + addname
        pickle.dump(dt, open(savefile, 'wb'))
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#4682B4]Model Saved[/#4682B4]")
        console.print(table)
    else:
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#FF8C00]Model Not Saved[/#FF8C00]")
        console.print(table)
        pass


def trainLogisticRegression():
    # Select Dataset from Folder
    table = Table(show_header=False, title="\n[#8A2BE2]List of Datasets:[/#8A2BE2]", box=box.HORIZONTALS)
    basepath = 'datafolder/'
    for entry in os.listdir(basepath):
        name, ext = os.path.splitext(entry)
        if os.path.isfile(os.path.join(basepath, entry)):
            if ext == '.csv':
                table.add_row(entry)
    console.print(table)
    check = input("\nInput Data: ")
    os.listdir(basepath)
    idsdata = pd.read_csv(basepath + check)
    df = pd.DataFrame(idsdata)

    # Data Clean
    df = df.replace([np.inf, -np.inf], np.nan).dropna(axis=0)
    df['Timestamp'] = df['Timestamp'].str.replace(" ", "") \
        .str.replace("/", "").str.replace(":", "")
    X = df.iloc[:, :-1].values
    y = df.iloc[:, -1].values

    # Select Test Size
    testsize = float(click.prompt('\nInput test size: [float value]'))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize, random_state=0)

    # Machine Learning
    from sklearn.linear_model import LogisticRegression
    logreg = LogisticRegression(solver='sag')
    logreg.fit(X_train, y_train)
    y_pred = logreg.predict(X_test)

    # Print Output
    from sklearn import metrics
    table = Table(title="\nLogistic Regression Result: ", show_header=True, header_style="bold magenta")
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
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))


def trainSVM():
    # Still in progress
    # Input Reading Of Data
    data = click.prompt('Input your dataset: ')
    idsdata = pd.read_csv(data)
    df = pd.DataFrame(idsdata)

    df = df.replace([np.inf, -np.inf], np.nan).dropna(axis=0)
    df['Timestamp'] = df['Timestamp'].str.replace(" ", "") \
        .str.replace("/", "").str.replace(":", "")
    X = df.iloc[:, :-1].values
    y = df.iloc[:, -1].values
    print('Data cleaned')
    # Machine Learning
    from sklearn import svm
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=109)

    clf = svm.SVC(kernel='linear')
    print('algo activated')
    np.nan_to_num(X_train)
    np.nan_to_num(y_train)
    print('nan to num')

    from sklearn import preprocessing
    X_train = preprocessing.minmax_scale(X_train)
    X_test = preprocessing.minmax_scale(X_test)
    # y_train = preprocessing.scale(y_train)

    clf.fit(X_train, y_train)
    print('model fitted')
    y_pred = clf.predict(X_test)
    print('model predicted')

    # Print Output
    from sklearn import metrics
    table = Table(title="\nSVM Result: ", show_header=True, header_style="bold magenta")
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
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))




def trainGaussianNB():
    # Select Dataset from Folder
    table = Table(show_header=False, title="\n[#8A2BE2]List of Datasets:[/#8A2BE2]", box=box.HORIZONTALS)
    basepath = 'datafolder/'
    for entry in os.listdir(basepath):
        name, ext = os.path.splitext(entry)
        if os.path.isfile(os.path.join(basepath, entry)):
            if ext == '.csv':
                table.add_row(entry)
    console.print(table)
    check = input("\nInput Data: ")
    os.listdir(basepath)
    idsdata = pd.read_csv(basepath + check)
    df = pd.DataFrame(idsdata)

    # Data Clean
    df = df.replace([np.inf, -np.inf], np.nan).dropna(axis=0)
    df['Timestamp'] = df['Timestamp'].str.replace(" ", "") \
        .str.replace("/", "").str.replace(":", "")
    X = df.iloc[:, :-1].values
    y = df.iloc[:, -1].values

    # Select Test Size
    testsize = float(click.prompt('\nInput test size: [float value]'))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize, random_state=0)

    # Machine Learning
    from sklearn.naive_bayes import GaussianNB
    gnb = GaussianNB()
    gnb.fit(X_train, y_train)
    y_pred = gnb.predict(X_test)

    # Print Output
    from sklearn import metrics
    table = Table(title="\nGaussianNB Result: ", show_header=True, header_style="bold magenta")
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
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))

    # Save Function
    savepath = 'savedmodels/'
    save = (click.prompt(click.style('\nWould you like to save the trained model ?(Y/N)', fg='yellow')))
    if save == 'Y' or save == 'y':
        gnb.fit(X_train, y_train)
        rmext = os.path.splitext(check)[0]
        addname = os.path.join('(rfc)')
        savefile = savepath + rmext + addname
        pickle.dump(gnb, open(savefile, 'wb'))
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#4682B4]Model Saved[/#4682B4]")
        console.print(table)
    else:
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#FF8C00]Model Not Saved[/#FF8C00]")
        console.print(table)
        pass


def trainBernoulliNB():
    # Select Dataset from Folder
    table = Table(show_header=False, title="\n[#8A2BE2]List of Datasets:[/#8A2BE2]", box=box.HORIZONTALS)
    basepath = 'datafolder/'
    for entry in os.listdir(basepath):
        name, ext = os.path.splitext(entry)
        if os.path.isfile(os.path.join(basepath, entry)):
            if ext == '.csv':
                table.add_row(entry)
    console.print(table)
    check = input("\nInput Data: ")

    os.listdir(basepath)
    idsdata = pd.read_csv(basepath + check)
    df = pd.DataFrame(idsdata)

    # Data Clean
    df = df.replace([np.inf, -np.inf], np.nan).dropna(axis=0)
    df['Timestamp'] = df['Timestamp'].str.replace(" ", "") \
        .str.replace("/", "").str.replace(":", "")
    X = df.iloc[:, :-1].values
    y = df.iloc[:, -1].values

    # Select Test Size
    testsize = float(click.prompt('\nInput test size: [float value]'))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize)

    # Machine Learning
    from sklearn.naive_bayes import BernoulliNB
    bnb = BernoulliNB()
    bnb.fit(X_train, y_train)
    y_pred = bnb.predict(X_test)

    # Print Output
    from sklearn import metrics
    table = Table(title="\nBernoulliNB Result: ", show_header=True, header_style="bold magenta")
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
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))

    # Save Function
    savepath = 'savedmodels/'
    save = (click.prompt(click.style('\nWould you like to save the trained model ?(Y/N)', fg='yellow')))
    if save == 'Y' or save == 'y':
        bnb.fit(X_train, y_train)
        rmext = os.path.splitext(check)[0]
        addname = os.path.join('(rfc)')
        savefile = savepath + rmext + addname
        pickle.dump(bnb, open(savefile, 'wb'))
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#4682B4]Model Saved[/#4682B4]")
        console.print(table)
    else:
        table = Table(show_header=False, box=box.ROUNDED, safe_box=False)
        table.add_row("[#FF8C00]Model Not Saved[/#FF8C00]")
        console.print(table)
        pass


def trainAll():
    # Select Dataset from Folder
    table = Table(show_header=False, title="\n[#8A2BE2]List of Datasets:[/#8A2BE2]", box=box.HORIZONTALS)
    basepath = 'datafolder/'
    for entry in os.listdir(basepath):
        name, ext = os.path.splitext(entry)
        if os.path.isfile(os.path.join(basepath, entry)):
            if ext == '.csv':
                table.add_row(entry)
    console.print(table)
    check = input("\nInput Data: ")
    os.listdir(basepath)
    idsdata = pd.read_csv(basepath + check)
    df = pd.DataFrame(idsdata)

    # Data Clean
    df = df.replace([np.inf, -np.inf], np.nan).dropna(axis=0)
    df['Timestamp'] = df['Timestamp'].str.replace(" ", "") \
        .str.replace("/", "").str.replace(":", "")
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

    # Random Forest Classifier Output
    from sklearn import metrics
    table = Table(title="\nRandom Forest Classifier Results", show_header=True, header_style="bold magenta")
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
    RAcc = metrics.accuracy_score(y_test, y_pred)  # For Ranking
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

    # Decision Tree Classifier Output
    table = Table(title="\nDecision Tree Classifier Result: ", show_header=True, header_style="bold magenta")
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
    DAcc = metrics.accuracy_score(y_test, y_pred)  # For Ranking
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
    LAcc = metrics.accuracy_score(y_test, y_pred)  # For Ranking
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))

    # SVM

    # GaussianNB
    from sklearn.naive_bayes import GaussianNB
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize)
    gnb = GaussianNB()
    gnb.fit(X_train, y_train)
    y_pred = gnb.predict(X_test)

    # GaussianNB Output
    from sklearn import metrics
    table = Table(title="\nGaussianNB Result: ", show_header=True, header_style="bold magenta")
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
    GAcc = metrics.accuracy_score(y_test, y_pred)  # For Ranking
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))

    # BernoulliNB
    from sklearn.naive_bayes import BernoulliNB
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize)
    gnb = BernoulliNB()
    gnb.fit(X_train, y_train)
    y_pred = gnb.predict(X_test)

    # BernoulliNB Output
    from sklearn import metrics
    table = Table(title="\nBernoulliNB Result: ", show_header=True, header_style="bold magenta")
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
    BAcc = metrics.accuracy_score(y_test, y_pred)  # For Ranking
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))

    ranking = [RAcc, DAcc, LAcc, GAcc, BAcc]
    ranking.sort()
    print("\nSummary: ")
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
