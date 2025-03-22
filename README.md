**kickhash** is a small command-line utility that will check all files in a directory tree for changes using MD5 hashing. Written in Go and OS-agnostic.

On a first run, every file will have its MD5 computed and saved in a CSV file at the root of the directory being verified.

On any subsequent runs, if the CSV file is present, the utility will report files that have been added, deleted or modified or damaged since the previous run.

**kickhash** can also find duplicate files using the `-dupes` option.

# How to use

Just run `kickhash` from within the directory you want to verify or `kickhash c:\target\directory` for a different one. A *hashes.csv* file will be generated listing all files found, their size and MD5 hash.

To check for changes, run `kickhash` again. If the *hashes.csv* file is found, it'll start looking for changes and report them.

# Options

Use `kickhash -h` for help.

`kickhash -dupes` also finds and reports duplicate files.

`kickhash -hidden` will also include hidden files.

`kickhash -update` will update the csv file if one exists, along with reporting changes from the previous run.

`kickhash -hashname some_name.csv` will use a different name for the csv file than the default.

`kickhash -verbose` will produce more verbose output of what is going on.