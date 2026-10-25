# Examples and pictures

The 25 offline stories use aws.demo(), assert expected fixtures, export host-derived
CSV and draw with lmplot or lmdraw. They do not resolve AWS credentials. Each script
executes its own bytecode and writes images/name.png under the current directory.
README captions use complete raw-URL lmctl autorun commands. Run-owned write
examples simulate ledger/teardown through the same Sandbox API.

The examples renderer executes the actual example scripts, then copies their images
into docs/images. No substitute images or undocumented input files are used.
Gallery tests check PNG signatures/size, source paths, README URLs and execution.
Fresh-cache raw-URL autoruns are verified after the release is published.
