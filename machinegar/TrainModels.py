import click
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import os
from rich import *
from rich.console import Console
from rich.table import Column, Table
from decimal import Decimal
from rich.progress import track

console = Console()

import warnings

warnings.filterwarnings('ignore')  # "error", "ignore", "always", "default", "module" or "once"


def trainRandomForestClassifier():
    # Select Dataset from Folder
    basepath = 'datafolder/'
    for entry in os.listdir(basepath):
        name, ext = os.path.splitext(entry)
        if os.path.isfile(os.path.join(basepath, entry)):
            if ext == '.csv':
                print(entry)
    check = input("Input Data: ")
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
    testsize = float(click.prompt('Input test size: [float value]'))
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
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))


def trainDecisionTreeClassifier():
    # Select Dataset from Folder
    basepath = 'datafolder/'
    for entry in os.listdir(basepath):
        name, ext = os.path.splitext(entry)
        if os.path.isfile(os.path.join(basepath, entry)):
            if ext == '.csv':
                print("List of Datasets: ")
                print(entry)
    check = input("Input Data: ")
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
    testsize = float(click.prompt('Input test size: [float value]'))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize, random_state=1)

    # Machine Learning
    from sklearn.tree import DecisionTreeClassifier
    dt = DecisionTreeClassifier()
    np.nan_to_num(X_train)
    np.nan_to_num(y_train)
    dt.fit(X_train, y_train)
    y_pred = dt.predict(X_test)

    # Print Output
    from sklearn import metrics
    print("Decision Tree Classifier Result: ")
    print("Precision:", metrics.precision_score(y_test, y_pred, average='macro'))
    print("Recall:", metrics.recall_score(y_test, y_pred, average='macro'))
    print("Accuracy:", metrics.accuracy_score(y_test, y_pred))
    print("F1:", metrics.f1_score(y_test, y_pred, average='macro'))
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))


def trainLogisticRegression():
    # Select Dataset from Folder
    print("List of Datasets: ")
    basepath = 'datafolder/'
    for entry in os.listdir(basepath):
        name, ext = os.path.splitext(entry)
        if os.path.isfile(os.path.join(basepath, entry)):
            if ext == '.csv':
                print(entry)
    check = input("Input Data: ")
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
    testsize = float(click.prompt('Input test size: [float value]'))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize, random_state=0)

    # Machine Learning
    from sklearn.linear_model import LogisticRegression
    logreg = LogisticRegression(solver='sag')
    logreg.fit(X_train, y_train)
    y_pred = logreg.predict(X_test)

    # Print Output
    from sklearn import metrics
    print("Logistic Regression Result: ")
    print("Precision:", metrics.precision_score(y_test, y_pred, average='macro'))
    # print("Recall:", metrics.recall_score(y_test, y_pred, average='macro'))
    # print("Accuracy:", metrics.accuracy_score(y_test, y_pred))
    # print("F1:", metrics.f1_score(y_test, y_pred, average='macro'))
    # print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))


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
    from sklearn import metrics

    print("SVM Result: ")
    print("Precision:", metrics.precision_score(y_test, y_pred, average='macro'))
    print("Recall:", metrics.recall_score(y_test, y_pred, average='macro'))
    print("Accuracy:", metrics.accuracy_score(y_test, y_pred))
    print("F1:", metrics.f1_score(y_test, y_pred, average='macro'))
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))


def trainGaussianNB():
    # Select Dataset from Folder
    basepath = 'datafolder/'
    for entry in os.listdir(basepath):
        name, ext = os.path.splitext(entry)
        if os.path.isfile(os.path.join(basepath, entry)):
            if ext == '.csv':
                print("List of Datasets: ")
                print(entry)
    check = input("Input Data: ")
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
    testsize = float(click.prompt('Input test size: [float value]'))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize, random_state=0)

    # Machine Learning
    from sklearn.naive_bayes import GaussianNB
    gnb = GaussianNB()
    gnb.fit(X_train, y_train)
    y_pred = gnb.predict(X_test)

    # Print Output
    from sklearn import metrics
    print("GaussianNB Result: ")
    print("Accuracy:", metrics.accuracy_score(y_test, y_pred))
    print("Precision:", metrics.precision_score(y_test, y_pred, average='macro'))
    print("Recall:", metrics.recall_score(y_test, y_pred, average='macro'))
    print("Accuracy:", metrics.accuracy_score(y_test, y_pred))
    print("F1:", metrics.f1_score(y_test, y_pred, average='macro'))
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))


def trainBernoulliNB():
    # Select Dataset from Folder
    basepath = 'datafolder/'
    for entry in os.listdir(basepath):
        name, ext = os.path.splitext(entry)
        if os.path.isfile(os.path.join(basepath, entry)):
            if ext == '.csv':
                print("List of Datasets: ")
                print(entry)
    check = input("Input Data: ")
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
    testsize = float(click.prompt('Input test size: [float value]'))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize)

    # Machine Learning
    from sklearn.naive_bayes import BernoulliNB
    gnb = BernoulliNB()
    gnb.fit(X_train, y_train)
    y_pred = gnb.predict(X_test)

    # Print Output
    from sklearn import metrics
    print("BernoulliNB Result: ")
    print("Accuracy:", metrics.accuracy_score(y_test, y_pred))
    print("Precision:", metrics.precision_score(y_test, y_pred, average='macro'))
    print("Recall:", metrics.recall_score(y_test, y_pred, average='macro'))
    print("Accuracy:", metrics.accuracy_score(y_test, y_pred))
    print("F1:", metrics.f1_score(y_test, y_pred, average='macro'))
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))


def trainAll():
    # Select Dataset from Folder
    basepath = 'datafolder/'
    print("List of Datasets: ")
    for entry in os.listdir(basepath):
        name, ext = os.path.splitext(entry)
        if os.path.isfile(os.path.join(basepath, entry)):
            if ext == '.csv':
                print(entry)
    check = input("Input Data: ")
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

trainAll()