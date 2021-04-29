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

    print("Precision:", metrics.precision_score(y_test, y_pred, average='macro'))
    print("Recall:", metrics.recall_score(y_test, y_pred, average='macro'))
    print("Accuracy:", metrics.accuracy_score(y_test, y_pred))
    print("F1:", metrics.f1_score(y_test, y_pred, average='macro'))
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))


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

    print("Precision:", metrics.precision_score(y_test, y_pred, average='macro'))
    print("Recall:", metrics.recall_score(y_test, y_pred, average='macro'))
    print("Accuracy:", metrics.accuracy_score(y_test, y_pred))
    print("F1:", metrics.f1_score(y_test, y_pred, average='macro'))
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))


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
    logreg = LogisticRegression(solver='sag')
    logreg.fit(X_train, y_train)
    y_pred = logreg.predict(X_test)

    from sklearn import metrics
    print("Precision:", metrics.precision_score(y_test, y_pred, average='macro'))
    print("Recall:", metrics.recall_score(y_test, y_pred, average='macro'))
    print("Accuracy:", metrics.accuracy_score(y_test, y_pred))
    print("F1:", metrics.f1_score(y_test, y_pred, average='macro'))
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))
    # import seaborn as sns
    # import matplotlib.pyplot as plt
    # y_axis_labels = y_pred
    # sns.heatmap(metrics.confusion_matrix(y_test, y_pred), annot=True, yticklabels=y_axis_labels)
    # plt.show()


def trainSVM():
    # Still in progress
    # Input Reading Of Data
    data = click.prompt('Input your dataset: ')
    idsdata = pd.read_csv(data)
    df = pd.DataFrame(idsdata)

    # idsdata = pd.read_csv('IDS1718_Dataset.csv')
    # df = pd.DataFrame(idsdata)
    # print('Dataframed')
    # Data Clean
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

    print("Precision:", metrics.precision_score(y_test, y_pred, average='macro'))
    print("Recall:", metrics.recall_score(y_test, y_pred, average='macro'))
    print("Accuracy:", metrics.accuracy_score(y_test, y_pred))
    print("F1:", metrics.f1_score(y_test, y_pred, average='macro'))
    print("Confusion Matrix: \n", metrics.confusion_matrix(y_test, y_pred))

# def trainGaussianNB():
#