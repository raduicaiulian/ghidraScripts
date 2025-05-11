run: export GHIDRA_INSTALL_DIR=/home/i/Downloads/ghidra_11.3_PUBLIC
# nu este bine că am binarul de test în afara repoului, ar trebuii pus pe un server de artefacte
run: export PATH_TO_PROGRAM_TO_ANALYSE=/home/i/repos/CFG_Malware_Script_Thingy/samples/example_binary.bin
run: export OUTPUT_DIRECTORY=/home/i/repos/ghidraScripts/python/artifacts/

run:
	python3 program.py

clean:
	rm -rf example_binary.log example_binary.dot artifacts