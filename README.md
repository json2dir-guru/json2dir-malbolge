# json2dir-malbolge

json2dir in Malbolge Unshackled: `json2dir.c` is compiled with ELVM (8cc, HeLL backend) and LMFAO into the 250 MB Malbolge program `json2dir.mal` (shipped as `json2dir.mal.xz`, rebuilt by `build.sh`), which validates the document and prints a shell script; the POSIX sh launcher `json2dir` runs it with a fixed-width-20 Malbolge Unshackled interpreter. Expect 30–60 s per document.

    xz -dk json2dir.mal.xz && JSON2DIR_MU=/path/to/mu20fast ./json2dir < tree.json
