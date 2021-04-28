import click
import pandas as pd
import numpy as np
from sklearn import *
from sklearn.model_selection import train_test_split


def trainRandomForestClassifier():
    # Input Reading Of Data
    data = click.prompt('Input your dataset: ')
    idsdata = pd.read_csv(data)
    df = pd.DataFrame(idsdata)

    # Data Clean
    df = df.replace([np.inf, -np.inf], np.nan).dropna(axis=0)
    df['Timestamp'] = df['Timestamp'].str.replace(" ", "") \
        .str.replace("/", "").str.replace(":", "")
    X = df.iloc[:, :-1].values
    y = df.iloc[:, -1].values

    # Machine Learning
    testsize = float(click.prompt('Input test size: [float value]'))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize, random_state=0)

    from sklearn.ensemble import RandomForestClassifier

    clf = RandomForestClassifier(n_estimators=300)

    np.nan_to_num(X_train)
    np.nan_to_num(y_train)

    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    from sklearn import metrics

    print("Accuracy:", metrics.accuracy_score(y_test, y_pred))


def trainDecisionTreeClassifier():
    # Input Reading Of Data
    data = click.prompt('Input your dataset: ')
    idsdata = pd.read_csv(data)
    df = pd.DataFrame(idsdata)

    # Data Clean
    df = df.replace([np.inf, -np.inf], np.nan).dropna(axis=0)
    df['Timestamp'] = df['Timestamp'].str.replace(" ", "") \
        .str.replace("/", "").str.replace(":", "")
    X = df.iloc[:, :-1].values
    y = df.iloc[:, -1].values

    # Machine Learning
    from sklearn.tree import DecisionTreeClassifier
    testsize = float(click.prompt('Input test size: [float value]'))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=testsize, random_state=1)

    dt = DecisionTreeClassifier()

    np.nan_to_num(X_train)
    np.nan_to_num(y_train)

    dt.fit(X_train, y_train)
    y_pred = dt.predict(X_test)
    from sklearn import metrics

    print("Accuracy:", metrics.accuracy_score(y_test, y_pred))


def trainLogisticRegression():
    # Input Reading Of Data
    data = click.prompt('Input your dataset: ')
    idsdata = pd.read_csv(data)
    df = pd.DataFrame(idsdata)

    # Data Clean
    df = df.replace([np.inf, -np.inf], np.nan).dropna(axis=0)
    df['Timestamp'] = df['Timestamp'].str.replace(" ", "") \
        .str.replace("/", "").str.replace(":", "")
    X = df.iloc[:, :-1].values
    y = df.iloc[:, -1].values

    # Machine Learning
    from sklearn.linear_model import LogisticRegression
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=0)
    logreg = LogisticRegression(max_iter=16000)
    logreg.fit(X_train, y_train)
    y_pred = logreg.predict(X_test)
    from sklearn import metrics
    # print('Accuracy of logistic regression classifier on test set: {:.2f}'.format(logreg.score(X_test, y_test)))
    print("Accuracy:", metrics.accuracy_score(y_test, y_pred))
