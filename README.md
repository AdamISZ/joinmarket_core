# joinmarket_core
Experimental repo for package structure of core joinmarket code, 
allowing easier plugging in to other projects.

Just some notes to start:

Intention is to create a package that can be installed and then used in other
wallet code or similar.

Broad plan:

The current joinmarket/ directory in Joinmarket-Org/joinmarket/joinmarket
is maintained, but renamed to joinmarket_core as a python package.
There is an additional file `btc.py` which acts as an interface. By default it will
access the current Bitcoin code as in Joinmarket-Org/joinmarket/bitcoin, but other
interfaces can be added. So far, an interface using the Electrum library has been
added and rudimentarily tested.

The idea of the workflow is:

```
pip install libnacl
#Either:
python setup.py install #from joinmarket_core
#Or:
pip install joinmarket_core
pip install secp256k1 #will probably only apply to full Joinmarket; other wallets have their own ECC bindings
```

then code can be written that uses the joinmarket_core package. Work on this for
Electrum is in progress.

=====

Running the test `python test_btc_interface.py` currently requires either the Joinmarket
`bitcoin` directory or the Electrum core library (`electrum/lib`) to be accessible on the path.

The structure of that interface (the contents of `joinmarket_core/btc.py` needs to be figured out).

