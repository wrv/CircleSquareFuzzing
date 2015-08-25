import subprocess, sys, os, time, shutil, signal

from os import listdir, makedirs
from os.path import isfile, join, exists

curPro = "" # this is the program we are analyzing. Full path
fuzzInDir = "" # the input directory for the fuzzing
fuzzOutDir = "" # this is the directory we are exploring (also output directory to fuzzing)
outDir = "" # the output directory for our results
fuzzerPro = "" # the link to the fuzzer program
secondProgs = [] # the list of secondary programs to test

verificationRun = 12 # the number of times to rerun the same file for verification

gdbOutputs = {}

usageString = '''Usage: ScriptName -pi </lol/input> -po </lol/output> -p </lol/program> -f </lol/fuzz> -o </lol/lol/> -s <lol1> <lol2> ...
	-pi <input folder for the program to fuzz> 
	-po <output folder for the program to fuzz. Also source for secondary tests>
	-p <program to fuzz>
	-f <the fuzzer>
	-o <the directory for this scripts output>
	-s <link to secondary programs to explore. Leave at end>'''

##
# If there is malformed input or some user-based error then print this
def printUsageAndExit(missingElem):
	print "Error: " + missingElem
	print usageString
	sys.exit(0)

##
# In case of Interrupt being pressed, we save our intermediate responses
def signal_handler(signal,frame):
	print "Ctrl+C Pressed! Saving current work"
	writeResultsToFile()
	sys.exit(0)

##
# folderMonitor
# @input - path: the path to the folder we want to monitor
#
# monitors a folder for file changes and returns the list of 
# newly generated files
def folderMonitor(path):
	time.sleep(5) # give it some time to get the fuzzer running
	emptyCount = 0
	filepath = join(path,"queue")
	files = listdir(filepath)
	while(1):
		lastElem = files[-1]
		#print "current files: " + str(files)
		# if we have empty files then quit
		if files == []:
			emptyCount += 1
			if emptyCount > 50:
				break
			time.sleep(2)
		else:
			if ".state" in files:
				files.remove(".state")
			runProg(files, filepath)

		newfiles = listdir(filepath)
		files = newfiles[newfiles.index(lastElem):] # So we don't have to do repetitions

##
# Run the programs in secondProgs list against the files gotten from
# folderMonitor. We run each program in gdb 
def runProg(files, filepath):
	global gdbOutputs

	command1 = "echo run | gdb --args "
	command2 = " lol.png"
	
	curResults = []

	for prog in secondProgs:
		#gdbOutputs[prog] = []
		curResults.append(0) # initialize the curResults
		
	for f in files:
		for prog in secondProgs:
			ffpath = join(filepath,f) #full file path
			verRuns = []
			for i in range(verificationRun):
				
				lecommand = command1 + prog + " " + ffpath + command2
				
				#print "\nrunning program with command: " + lecommand
				
				# Run the program with the input
				cmdOutput = subprocess.check_output(lecommand, shell=True)
				#gdbCleaned = cleanUpText(cmdOutput)

				## we only care about crashes, or segmentation faults (SIGSEGV)
				if "SIGSEGV" in cmdOutput:
					verRuns.append(1)
				else:
					verRuns.append(0)
				## we now keep track of the different outputs
				#if gdbCleaned not in gdbOutputs[prog]:
				#	gdbOutputs[prog].append(gdbCleaned)

			#we assume that if more than half of the runs resulted in a crash then it's a valid crash
			if sum(verRuns) >= verificationRun/2:
				curResults[secondProgs.index(prog)] = 1
			else:
				curResults[secondProgs.index(prog)] = 0
		# We want to store the results if we had a crash
		print f,curResults
		if 1 in curResults:
			gdbOutputs[f] = curResults # the file is the key to the run results
			saveFile(ffpath)


##
# takes in the filepath of an interesting file and saves it in
# outDir/coolFiles/
def saveFile(filePath):
	os.system('cp ' + filePath + ' ' + join(outDir,"coolFiles"))


##
# parses the gdboutput to only keep info we care about
# we want to be able to organize the results of each run through version
# and if a crash is successful or not. 
def cleanUpText(gdbOutput):
	cleanedUp = ''
	lines = gdbOutput.split('\n')
	if "exited normally" in gdbOutput:
		return "exited normally"

	for i in range(len(lines)):
		if i > 10  and len(lines)-i > 3: # we want to skip the first 10 lines as well as the last 3
			cleanedUp += lines[i] + '\n'
	return cleanedUp

##
# Writes the gdb output to a file for later analysis
#
def writeResultsToFile():
	global gdbOutputs
	f = open(join(outDir,"gdbOutput"),'w')
	f.write(' '.join(secondProgs) + '\n')

	for key, value in gdbOutputs.iteritems():
		toWrite = (key,value)
		f.write(str(toWrite) + '\n')


##
# begin the fuzzer which should be generating the files for testing
# the assumption is that afl-fuzz is being used so we are working with
# it's directory structure. 
# We also assume this script is strictly for our ImageMagick purposes. 
# Can be repurposed for more general applications later
def beginFuzzer(fuzzerPro, curPro, fuzzInDir, fuzzOutDir):
	command = fuzzerPro + " -i " + fuzzInDir + " -o " + fuzzOutDir + " -- " + curPro + " @@ @@.png"
	print "starting fuzzer with command: " + command
	if not exists(fuzzOutDir):
		makedirs(fuzzOutDir)
	else:
		shutil.rmtree(fuzzOutDir)
		makedirs(fuzzOutDir)
	# run the fuzzer 
	# we use os.spawnl because we want it to run in the background
	subprocess.Popen(command, shell=True)
	#os.spawnl(os.P_NOWAIT, command)
	# monitor folder
	
	#print "verifying program is running"
	#os.system("ps aux | grep afl")
	
	#print "beginning to monitor folders"
	
	folderMonitor(fuzzOutDir)

##
# parse the given arguments and properly assign variables
def parseArgs(args):
	global curPro
	global fuzzerPro
	global fuzzInDir
	global fuzzOutDir
	global outDir
	global secondProgs

	verbose = False #printing of the process

	#we need to check the proper arguments were passed in
	if '-pi' not in args:
		printUsageAndExit("-pi")
	if '-po' not in args:
		printUsageAndExit("-po")
	if '-p' not in args:
		printUsageAndExit("-p")
	if '-f' not in args:
		printUsageAndExit("-f")
	if '-o' not in args:
		printUsageAndExit("-o")
	if '-v' in args:
		verbose = True
	if '-s' not in args:
		printUsageAndExit("-s")

	fuzzInDir = args[args.index('-pi')+1]
	fuzzOutDir = args[args.index('-po')+1]
	curPro = args[args.index('-p')+1]
	fuzzerPro = args[args.index('-f')+1]
	outDir = args[args.index('-o')+1]
	secondProgs = args[args.index('-s')+1:]
	
	if not exists(outDir):
		makedirs(outDir)
	
	beginFuzzer(fuzzerPro=fuzzerPro, curPro=curPro, fuzzInDir=fuzzInDir, fuzzOutDir=fuzzOutDir)


signal.signal(signal.SIGINT, signal_handler)

##
# so we can run the script from terminal
if __name__ == "__main__":
	parseArgs(sys.argv[1:]) # ignore the program name

