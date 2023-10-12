This folder contains the helper scripts of the signature scheme.
For the details on how to run the security estimator and precise syntax, please use python3 FS_security_estimates.py --help.

The option --param can be used to compute the security of a given parameter set.
When some parameter set should be compared with the state of the art parameters, add the option --record_xxx, where xxx is 120, 180 or 260.

A list of suitable modulus q can be computed by running qlist.py.
The ring dimension should be taken n=256.
