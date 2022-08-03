## EBAT
Embedded Binary Analysis Tool

### Docker build (takes time)
1. `docker build --tag ebat .`


### Firmware image analysis
1. Minimal example (required only):
- `-c` configuration file
- `-i` firmware image folder that contains the firmware images to analyse
- `-o` output folder
```bash
docker run -i -t --rm -v $PWD:/EBAT:rw --privileged \
       ebat python3 /EBAT/main.py \
       -c /EBAT/configurations/debat.cfg \
       -i /EBAT/Firmwares/test/ \
       -o /EBAT/resultsd/Firmwares/test/
```

### Firmware images multiple analysis
1. Create a release file
- \# is parsed as comment
- per line delimiter `;`
- 1st column firmware image file
- 2nd column date with format DD/MM/YYYY
- 3rd set of products name (multiple firmware images may be used in multiple product lines)
```
firmware1.zip; date; {'product name'}
firmware2.zip; date; {'product name'}

Example file: `ReleaseDates.csv`

```csv
# Release dates:
DIR-XXXX_REVA_FIRMWARE_v1.03B02.zip; 14/08/2020; {'DIR-XXX'}
DIR-XXXX_REVA_FIRMWARE_v1.04B04.zip; 18/02/2021; {'DIR-XXX'}
```

2. Run Firmware image analysis


### Command line arguments

NAME

       main.py - EBAT main script

SYNOPSIS

       python3 main.py [OPTIONS]... -i [INPUT FILE] -O [OUTPUT DIRECTORY] -c [configuration file]

DESCRIPTION

	MANDATORY:

       -i, --input
              Input firmware image

       -o, --output
              Output of the analysis

       -c, --config
              Configuration file for EBAT tools and more

    OPTIONAL:
	
        --save-executables
            Save files that are analysed into a different directory
       
        --save-ast
            Save Abstract Syntax Trees for each binary"
       
        --save-callgraph
            Save Callgraphs for each binary
       
        --save-ghidra
            Save Ghidra created Projects for each binary"
       
        --save-analysis
            Save Analysis total output to a separate file
       
        --delete-extract
            Delete firmware's extraction results after analysis
       
        -d, --debug, 
            Debugging information
       
        -v, --verbose
            Verbose information
       
        -x, --exclude-list
            Apply exclude list for binaries not to analysed by Ghidra. (configured in configuration file)
       
        -t, --threads
            Number of threads to run. Omitting the option, system will automatically identify the number of cores
       
        -l, --level
            Level of Ghidra Analysis. Level = 1: Default analysis, Level = 2: Decompiler Parameter ID, Level = 3: Aggressive Instruction search
       
        -id, --dates, 
            CSV file with release dates on each firmware