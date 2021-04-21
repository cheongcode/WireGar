import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt


def trainRandomForestClassifier():
    idsdata = pd.read_csv('IDS1718_Dataset.csv')

    df = pd.DataFrame(idsdata)
    df = df.replace([np.inf, -np.inf], np.nan).dropna(axis=0)
    df['Timestamp'] = df['Timestamp'].str.replace(" ", "") \
        .str.replace("/", "").str.replace(":", "")
    X = df.iloc[:, :-1].values
    y = df.iloc[:, -1].values

    from sklearn.model_selection import train_test_split

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=0)

    from sklearn.ensemble import RandomForestClassifier

    clf = RandomForestClassifier(n_estimators=300)

    np.nan_to_num(X_train)
    np.nan_to_num(y_train)

    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    from sklearn import metrics

    print("Accuracy:", metrics.accuracy_score(y_test, y_pred))
    # print(y_train)
    # feature_imp = pd.Series(clf.feature_importances_, index=y_train).sort_values(ascending=False)
    #
    # # Creating a bar plot
    # sns.barplot(x=feature_imp, y=feature_imp.index)
    # # Add labels to your graph
    # plt.xlabel('Feature Importance Score')
    # plt.ylabel('Features')
    # plt.title("Visualizing Important Features")
    # plt.legend()
    # plt.show()


