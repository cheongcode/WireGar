import time
import click


def printProgressBar(iteration, total, prefix='', suffix='', decimals=1, length=100, fill='█', printEnd="\r"):
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=printEnd)
    # Print New Line on Complete
    if iteration == total:
        print()


def progress():
    """
    Demonstrates how a progress bar can be tied to processing of
    an iterable - this time with colorful output.
    """

    iterable = range(256)

    fill_char = click.style("#", fg="green")
    empty_char = click.style("-", fg="white", dim=True)
    label_text = "Loading Gar..."

    with click.progressbar(
            iterable=iterable,
            label=label_text,
            fill_char=fill_char,
            empty_char=empty_char
    ) as items:
        for item in items:
            # Do some processing
            time.sleep(0.01)  # This is really hard work


def load():
    items = list(range(0, 57))
    l = len(items)
    # Initial call to print 0% progress
    printProgressBar(0, l, prefix='Loading Gar...', suffix='Complete', length=50)
    for i, item in enumerate(items):
        time.sleep(0.01)
        # Update Progress Bar
        printProgressBar(i + 1, l, prefix='Loading Gar...', suffix='Complete', length=50)


def logo():
    print(r"""
    MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
    MMMMy+++oNMy++/+mMd++++mm++/+dMs++++++++smMMh+++++++++dMMms/:::/smMMMMMNo+++++oNMMMN+++++++++yNMMMMM
    MMMM-    sN     /M-    yo    /m           yM-         oM+         +MMMM+       +MMMs          .mMMMM
    MMMMs    -h     `d     mo    /m     o-    .M-    :oooomy    ./-    yMMm        `mMMo    .o.    +MMMM
    MMMMm     :      -    -Mo    /m     h+    :M-    .:::mMo    mmssssyMMM/   .d`   +MMo    -h-    sMMMM
    MMMMM-                oMo    /m          .mM-        hMo    Ny.    oMd    /o:    mMo          /MMMMM
    MMMMMo       y:       dMo    /m     `    `NM-    +hddMMo    smy    +M-           /Mo    `     /MMMMM
    MMMMMm       ms      `MMo    /m     o     oM-         ym`         `dh    `::-     do    :-     mMMMM
    MMMMMM/     :MN.     oMMs    om`   .N-    :M/         sMm/`     `/mM/    yMMMo    oy    +h`    sMMMM
    MMMMMMMNNNNNMMMMNNNNNMMMMNmmNMMMNNNMMMNNNNMMMNNNNNNNNNMMMMMmdddmMMMMMNNNNMMMMMNNNNMMNNNNMMMNNNNMMMMM
    MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
    MMMMMmsyNMMMMMMMMMMMMNyoooshmMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
    MMMMM`  `+mMMMMMMMMMo`      ./ydhysso+++////:::::::::::///++oossyyhdmNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
    MMMMMy     -smMMMMM+    -///-`                                         `.-:oymMMMMMMMMMMMMMMMMMMMMMM
    MMMMMMd`      -+ydm/////-                                                     `:ohNMMMMMMMMMMMMMMMMM
    MMMMMMM+                                                                -          .+ymMMMMMMMMMMMMM
    MMMMMMM-                                                               s-     s-       ./yhhhhdNMMMM
    MMMMMh-         -+shdo///////:-.                                      `s                        /MMM
    MMMM+       `/yNMMMMs        `+mMNmdhyysoo++//::::----:::://++oosyyy///++`    ``..--:://++oossyydMMM
    MMMs     .+hMMMMMMMN      ./yNMMMMMMMMMMMMMMMh `.mMMMMMMMMMMMMMMMMN.   -NMNMMMMMMMMMMMMMMMMMMMMMMMMM
    MMMy` -odMMMMMMMMMMMy/+shNMMMMMMMMMMMMMMMMMMm. :mMMMMMMMMMMMMMMMMMo   +NMMMMMMMMMMMMMMMMMMMMMMMMMMMM
    MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMh`.yMMMMMMMMMMMMMMMMMMN. -hMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
    MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNdMMMMMMMMMMMMMMMMMMMMmohMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
    MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
    MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
          """)
