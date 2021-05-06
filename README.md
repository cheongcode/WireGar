# WireGar

Welcome to WireGar. An all-in-one forensic tool for network packet conversion and machine learning 
in an attempt to get good grades created by Brandon Cheong 

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install requirements.txt in 
your shell.

```bash
pip install -r requirements.txt
```

## Command Line Usage

```python
machinegar train1 [Input File] # Trains the model with Random Forest Classifier
netgar getlive # Gets 10 seconds of live network data
flowgar getflow [Input File] [Output File] # Converts a PCAP file to a CSV 'flow' file
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
Please make sure to update tests as appropriate.

Hope I get an A out of this...